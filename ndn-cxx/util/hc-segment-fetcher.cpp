/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2020 Regents of the University of California,
 *                         Colorado State University,
 *                         University Pierre & Marie Curie, Sorbonne University.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#include "ndn-cxx/util/hc-segment-fetcher.hpp"
#include "ndn-cxx/name-component.hpp"
#include "ndn-cxx/encoding/buffer-stream.hpp"
#include "ndn-cxx/lp/nack.hpp"
#include "ndn-cxx/lp/nack-header.hpp"

#include <boost/asio/io_service.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/thread.hpp>
#include <boost/bind.hpp>

#include <cmath>
#include <iostream>

#include <stdlib.h>


//#include "ndn-cxx/hash-data.hpp"

namespace ndn {
namespace util {

constexpr double HCSegmentFetcher::MIN_SSTHRESH;

void
HCSegmentFetcher::Options::validate()
{
  if (maxTimeout < 1_ms) {
    NDN_THROW(std::invalid_argument("maxTimeout must be greater than or equal to 1 millisecond"));
  }

  if (initCwnd < 1.0) {
    NDN_THROW(std::invalid_argument("initCwnd must be greater than or equal to 1"));
  }

  if (aiStep < 0.0) {
    NDN_THROW(std::invalid_argument("aiStep must be greater than or equal to 0"));
  }

  if (mdCoef < 0.0 || mdCoef > 1.0) {
    NDN_THROW(std::invalid_argument("mdCoef must be in range [0, 1]"));
  }
}

HCSegmentFetcher::HCSegmentFetcher(Face& face,
                               security::v2::Validator& validator,
                               const HCSegmentFetcher::Options& options)
  : m_options(options)
  , m_face(face)
  , m_scheduler(m_face.getIoService())
  , m_validator(validator)
  , m_rttEstimator(make_shared<RttEstimator::Options>(options.rttOptions))
  , m_timeLastSegmentReceived(time::steady_clock::now())
  , m_cwnd(options.initCwnd)
  , m_ssthresh(options.initSsthresh)
{
  m_options.validate();
}

shared_ptr<HCSegmentFetcher>
HCSegmentFetcher::start(Face& face,
                      const Interest& baseInterest,
                      security::v2::Validator& validator,
                      const HCSegmentFetcher::Options& options)
{
  shared_ptr<HCSegmentFetcher> fetcher(new HCSegmentFetcher(face, validator, options));
  fetcher->m_this = fetcher;
  fetcher->fetchFirstSegment(baseInterest, false);
  return fetcher;
}

void
HCSegmentFetcher:: stop()
{
  if (!m_this) {
    return;
  }

  m_pendingSegments.clear(); // cancels pending Interests and timeout events
  m_face.getIoService().post([self = std::move(m_this)] {});
}

bool
HCSegmentFetcher::shouldStop(const weak_ptr<HCSegmentFetcher>& weakSelf)
{
  auto self = weakSelf.lock();
  return self == nullptr || self->m_this == nullptr;
}

void
HCSegmentFetcher::fetchFirstSegment(const Interest& baseInterest, bool isRetransmission)
{
  Interest interest(baseInterest);
  interest.setCanBePrefix(true);
  interest.setMustBeFresh(true);
  interest.setInterestLifetime(m_options.interestLifetime);
  if (isRetransmission) {
    interest.refreshNonce();
  }

  sendInterest(0, interest, isRetransmission);
}

void
HCSegmentFetcher::fetchSegmentsInWindow(const Interest& origInterest)
{
  if (checkAllSegmentsReceived()) {
    // All segments have been retrieved
    return finalizeFetch();
  }

  int64_t availableWindowSize;
  if (m_options.inOrder) {
    availableWindowSize = std::min<int64_t>(m_cwnd, m_options.flowControlWindow - m_segmentBuffer.size());
  }
  else {
    availableWindowSize = static_cast<int64_t>(m_cwnd);
  }
  availableWindowSize -= m_nSegmentsInFlight;

  std::vector<std::pair<uint64_t, bool>> segmentsToRequest; // The boolean indicates whether a retx or not

  while (availableWindowSize > 0) {
    if (!m_retxQueue.empty()) {
      auto pendingSegmentIt = m_pendingSegments.find(m_retxQueue.front());
      m_retxQueue.pop();
      if (pendingSegmentIt == m_pendingSegments.end()) {
        // Skip re-requesting this segment, since it was received after RTO timeout
        continue;
      }
      BOOST_ASSERT(pendingSegmentIt->second.state == SegmentState::InRetxQueue);
      segmentsToRequest.emplace_back(pendingSegmentIt->first, true);
    }
    else if (m_nSegments == 0 || m_nextSegmentNum < static_cast<uint64_t>(m_nSegments)) {
      if (m_segmentBuffer.count(m_nextSegmentNum) > 0) {
        // Don't request a segment a second time if received in response to first "discovery" Interest
        m_nextSegmentNum++;
        continue;
      }
      segmentsToRequest.emplace_back(m_nextSegmentNum++, false);
    }
    else {
      break;
    }
    availableWindowSize--;
  }

  for (const auto& segment : segmentsToRequest) {
    Interest interest(origInterest); // to preserve Interest elements
    interest.setName(Name(m_versionedDataName).appendSegment(segment.first));
    interest.setCanBePrefix(false);
    interest.setMustBeFresh(true);
    interest.setInterestLifetime(m_options.interestLifetime);
    interest.refreshNonce();
    sendInterest(segment.first, interest, segment.second);
  }
}

void
HCSegmentFetcher::sendInterest(uint64_t segNum, const Interest& interest, bool isRetransmission)
{
  weak_ptr<HCSegmentFetcher> weakSelf = m_this;

  ++m_nSegmentsInFlight;
  auto pendingInterest = m_face.expressInterest(interest,
    [this, weakSelf] (const Interest& interest, const Data& data) {
      afterSegmentReceivedCb(interest, data, weakSelf);
    },
    [this, weakSelf] (const Interest& interest, const lp::Nack& nack) {
      afterNackReceivedCb(interest, nack, weakSelf);
    },
    nullptr);

  auto timeout = m_options.useConstantInterestTimeout ? m_options.maxTimeout : getEstimatedRto();
  auto timeoutEvent = m_scheduler.schedule(timeout, [this, interest, weakSelf] {
    afterTimeoutCb(interest, weakSelf);
  });

  if (isRetransmission) {
    updateRetransmittedSegment(segNum, pendingInterest, timeoutEvent);
    return;
  }

  PendingSegment pendingSegment{SegmentState::FirstInterest, time::steady_clock::now(),
                                pendingInterest, timeoutEvent};
  bool isNew = m_pendingSegments.emplace(segNum, std::move(pendingSegment)).second;
  BOOST_VERIFY(isNew);
  m_highInterest = segNum;
}

void
HCSegmentFetcher::afterSegmentReceivedCb(const Interest& origInterest, const Data& data,
                                       const weak_ptr<HCSegmentFetcher>& weakSelf)
{
  if (shouldStop(weakSelf))
    return;

  BOOST_ASSERT(m_nSegmentsInFlight > 0);
  m_nSegmentsInFlight--;

  name::Component currentSegmentComponent = data.getName().get(-1);
  if (!currentSegmentComponent.isSegment()) {
    return signalError(DATA_HAS_NO_SEGMENT, "Data Name has no segment number");
  }

  uint64_t currentSegment = currentSegmentComponent.toSegment();

  // The first received Interest could have any segment ID
  std::map<uint64_t, PendingSegment>::iterator pendingSegmentIt;
  if (m_receivedSegments.size() > 0) {
    pendingSegmentIt = m_pendingSegments.find(currentSegment);
  }
  else {
    pendingSegmentIt = m_pendingSegments.begin();
  }

  if (pendingSegmentIt == m_pendingSegments.end()) {
    return;
  }

  pendingSegmentIt->second.timeoutEvent.cancel();

  afterSegmentReceived(data);

  m_validator.validate(data,
                       bind(&HCSegmentFetcher::afterValidationSuccess, this, _1, origInterest,
                            pendingSegmentIt, weakSelf),
                       bind(&HCSegmentFetcher::afterValidationFailure, this, _1, _2, weakSelf));
}

void
HCSegmentFetcher::afterValidationSuccess(const Data& data, const Interest& origInterest,
                                       std::map<uint64_t, PendingSegment>::iterator pendingSegmentIt,
                                       const weak_ptr<HCSegmentFetcher>& weakSelf)
{
  if (shouldStop(weakSelf))
    return;

  //CRITICAL SECTION
  // processing_hashchain.lock();
  // boost::unique_lock<boost::mutex> scoped_lock(io_mutex);
  // We update the last receive time here instead of in the segment received callback so that the
  // transfer will not fail to terminate if we only received invalid Data packets.
  m_timeLastSegmentReceived = time::steady_clock::now();

  m_nReceived++;

  // It was verified in afterSegmentReceivedCb that the last Data name component is a segment number
  uint64_t currentSegment = data.getName().get(-1).toSegment();
  

  m_receivedSegments.insert(currentSegment);

  // Add measurement to RTO estimator (if not retransmission)
  if (pendingSegmentIt->second.state == SegmentState::FirstInterest) {
    BOOST_ASSERT(m_nSegmentsInFlight >= 0);
    m_rttEstimator.addMeasurement(m_timeLastSegmentReceived - pendingSegmentIt->second.sendTime,
                                  static_cast<size_t>(m_nSegmentsInFlight) + 1);
  }

  // Remove from pending segments map
  m_pendingSegments.erase(pendingSegmentIt);

  // Copy data 
  //m_dataBuffer.emplace(currentSegment, data);
  // std::copy(data.wireEncode().value_begin(), data.wireEncode().value_end(),
  //         receivedDataIt.first->second.get()->shared_from_this().get());

  // Copy data in segment to temporary buffer
 
  auto receivedSegmentIt = m_segmentBuffer.emplace(std::piecewise_construct,
                                                   std::forward_as_tuple(currentSegment),
                                                   std::forward_as_tuple(data.getContent().value_size()));

  std::copy(data.getContent().value_begin(), data.getContent().value_end(),
            receivedSegmentIt.first->second.begin());

  // std::copy(data.getContent().value_begin(), data.getContent().value_end(),
  //           receivedSegmentIt.first->second.begin());

  m_nBytesReceived += data.getContent().value_size();
  if(!m_options.inOrder){
    contentBuffer.write(m_segmentBuffer[currentSegment].get<const char>(), m_segmentBuffer[currentSegment].size());
  }
  afterSegmentValidated(data);

  if (data.getFinalBlock()) {
    if (!data.getFinalBlock()->isSegment()) {
      return signalError(FINALBLOCKID_NOT_SEGMENT,
                         "Received FinalBlockId did not contain a segment component");
    }

    if (data.getFinalBlock()->toSegment() + 1 != static_cast<uint64_t>(m_nSegments)) {
      m_nSegments = data.getFinalBlock()->toSegment() + 1;
      cancelExcessInFlightSegments();
    }
  }

  if(m_options.inOrder) {
    if (m_nextSegmentInOrder == currentSegment) {
      do {
        if(verifyHashChainData(data)){
          onInOrderVerifiedHashChainData(std::make_shared<Data>(data));
        } else {
          //hashchain error
        }
        onInOrderData(std::make_shared<const Buffer>(m_segmentBuffer[m_nextSegmentInOrder]));
        // m_dataBuffer.erase(m_nextSegmentInOrder);
        m_segmentBuffer.erase(m_nextSegmentInOrder);
        m_nextSegmentInOrder++;
      } while (m_segmentBuffer.count(m_nextSegmentInOrder) > 0);
    }
  } else { //BLOCK MODE
    if (m_nextSegmentInOrder == currentSegment) {
      do {
        verifyHashChainData(data);
        // m_dataBuffer.erase(m_nextSegmentInOrder);
        m_nextSegmentInOrder++;
      } while (m_segmentBuffer.count(m_nextSegmentInOrder) > 0);
    }
  }

  if (m_receivedSegments.size() == 1) {
    m_versionedDataName = data.getName().getPrefix(-1);
    if (currentSegment == 0) {
      // We received the first segment in response, so we can increment the next segment number
      m_nextSegmentNum++;
    }
  }

  if (m_highData < currentSegment) {
    m_highData = currentSegment;
  }

  if (data.getCongestionMark() > 0 && !m_options.ignoreCongMarks) {
    windowDecrease();
  }
  else {
    windowIncrease();
  }

  fetchSegmentsInWindow(origInterest);

  // processing_hashchain.unlock();
}

void
HCSegmentFetcher::afterValidationFailure(const Data& data,
                                       const security::v2::ValidationError& error,
                                       const weak_ptr<HCSegmentFetcher>& weakSelf)
{
  if (shouldStop(weakSelf))
    return;

  signalError(SEGMENT_VALIDATION_FAIL, "Segment validation failed: " + boost::lexical_cast<std::string>(error));
}

void
HCSegmentFetcher::afterNackReceivedCb(const Interest& origInterest, const lp::Nack& nack,
                                    const weak_ptr<HCSegmentFetcher>& weakSelf)
{
  if (shouldStop(weakSelf))
    return;

  afterSegmentNacked();

  BOOST_ASSERT(m_nSegmentsInFlight > 0);
  m_nSegmentsInFlight--;

  switch (nack.getReason()) {
    case lp::NackReason::DUPLICATE:
    case lp::NackReason::CONGESTION:
      afterNackOrTimeout(origInterest);
      break;
    default:
      signalError(NACK_ERROR, "Nack Error");
      break;
  }
}

void
HCSegmentFetcher::afterTimeoutCb(const Interest& origInterest,
                               const weak_ptr<HCSegmentFetcher>& weakSelf)
{
  if (shouldStop(weakSelf))
    return;

  afterSegmentTimedOut();

  BOOST_ASSERT(m_nSegmentsInFlight > 0);
  m_nSegmentsInFlight--;
  afterNackOrTimeout(origInterest);

}

void
HCSegmentFetcher::afterNackOrTimeout(const Interest& origInterest)
{
  if (time::steady_clock::now() >= m_timeLastSegmentReceived + m_options.maxTimeout) {
    // Fail transfer due to exceeding the maximum timeout between the successful receipt of segments
    return signalError(INTEREST_TIMEOUT, "Timeout exceeded");
  }

  name::Component lastNameComponent = origInterest.getName().get(-1);
  std::map<uint64_t, PendingSegment>::iterator pendingSegmentIt;
  BOOST_ASSERT(m_pendingSegments.size() > 0);
  if (lastNameComponent.isSegment()) {
    BOOST_ASSERT(m_pendingSegments.count(lastNameComponent.toSegment()) > 0);
    pendingSegmentIt = m_pendingSegments.find(lastNameComponent.toSegment());
  }
  else { // First Interest
    BOOST_ASSERT(m_pendingSegments.size() > 0);
    pendingSegmentIt = m_pendingSegments.begin();
  }

  // Cancel timeout event and set status to InRetxQueue
  pendingSegmentIt->second.timeoutEvent.cancel();
  pendingSegmentIt->second.state = SegmentState::InRetxQueue;

  m_rttEstimator.backoffRto();

  if (m_receivedSegments.size() == 0) {
    // Resend first Interest (until maximum receive timeout exceeded)
    fetchFirstSegment(origInterest, true);
  }
  else {
    windowDecrease();
    m_retxQueue.push(pendingSegmentIt->first);
    fetchSegmentsInWindow(origInterest);
  }
}

bool
HCSegmentFetcher::verifyHashChainData(const Data& data) {
  
  //boost::unique_lock<boost::mutex> scoped_lock(io_mutex);
  //std::cout<<"verifyHashChainData:"<<data.getName().get(-1).toSegment()<<std::endl;
  Name seqNo = data.getName().getSubName(-1);

    if(data.getSignatureInfo().hasNextHash() && (data.getSignatureType() == tlv::SignatureHashChainWithEcdsa || data.getSignatureType() == tlv::SignatureHashChainWithSha256)) {
        int segment = data.getName().get(-1).toSegment();
        int before_segment = segment - 1;

        auto myblock = data.getSignatureInfo().getNextHash().value();
        
        uint8_t* before_signature = nullptr;
        if(segment != 0){
        uint8_t* before_signature = m_nextHashBuffer[segment-1];
        }
        //std::cout<<"1========"<<std::endl;
        m_nextHashBuffer[segment] = new uint8_t[32];
        memcpy((void*)m_nextHashBuffer[segment], (void*)&(myblock.wire()[4]),32);

        if (segment != 0) {
          if (segment - 1 == before_segment) {
            //std::cout<<"2========"<<std::endl;
            // if(before_signature != nullptr && memcmp((void*)data.getSignatureValue().value(), (void*)before_signature->value(), data.getSignatureValue().value_size()+4)) {
            if(before_signature != nullptr && memcmp((void*)(&data.getSignatureValue().wire()[2]), (void*)before_signature, 32)) {
            
              delete[] before_signature;
              //====labry error
              signalError(HASHCHAIN_ERROR, "Failure hash key error: " + std::to_string(segment));
              return false;
              //afterSegmentValidated(data);
            } else {
              //std::cout<< "segment "<<data.getName().get(-1).toSegment()<<" validated"<< std::endl;
              delete[] before_signature;
              //free(signatureBytes);
              // success_count++;
              //afterSegmentValidated(data);
            }
          } else {
            //std::cout<<"not in order"<<std::endl;
            //This passes segment when a segment comes not in order.
            //afterSegmentValidated(data);
          }
        } else {
          //This falls for the first segment.

          // success_count++;
          //afterSegmentValidated(data);
        }
        //std::cout<<"verifyHashChainData mid: "<<data.getName().get(-1).toSegment()<<std::endl;
        int finalBlockId = data.getFinalBlock().value().toSegment();
        if (segment == finalBlockId) {
          //free(before_signature);
          delete[] m_nextHashBuffer[segment];
          // if (success_count < finalBlockId / 2) {
          //   std::cout << "Failure hash key error"<<std::endl;
          //   std::cout << "success_count:"<<success_count << std::endl;
          //   std::cout << "segment:"<<segment << std::endl;
          //   std::cout << "finalBlockId:"<<finalBlockId << std::endl;
            //onError(HASHCHAIN_ERROR, "Failure hash key error");
          // }
        }
      } 

      //std::cout<<"verifyHashChainData ended: "<<data.getName().get(-1).toSegment()<<std::endl;
      return true;
}


void
HCSegmentFetcher::finalizeFetch()
{
  if (m_options.inOrder) {
    onInOrderComplete();
  }
  else {
    // Combine segments into final buffer
    
    // We may have received more segments than exist in the object.
    BOOST_ASSERT(m_receivedSegments.size() >= static_cast<uint64_t>(m_nSegments));

    // onHashChainComplete(std::make_shared<stdstd::cout::map<uint64_t, Data>>(m_dataBuffer));
    onHashChainComplete(contentBuffer.buf());
    onComplete(contentBuffer.buf());
    contentBuffer.clear();
  }
  stop();
}

void
HCSegmentFetcher::windowIncrease()
{
  if (m_options.useConstantCwnd) {
    BOOST_ASSERT(m_cwnd == m_options.initCwnd);
    return;
  }

  if (m_cwnd < m_ssthresh) {
    m_cwnd += m_options.aiStep; // additive increase
  }
  else {
    m_cwnd += m_options.aiStep / std::floor(m_cwnd); // congestion avoidance
  }
}

void
HCSegmentFetcher::windowDecrease()
{
  if (m_options.disableCwa || m_highData > m_recPoint) {
    m_recPoint = m_highInterest;

    if (m_options.useConstantCwnd) {
      BOOST_ASSERT(m_cwnd == m_options.initCwnd);
      return;
    }

    // Refer to RFC 5681, Section 3.1 for the rationale behind the code below
    m_ssthresh = std::max(MIN_SSTHRESH, m_cwnd * m_options.mdCoef); // multiplicative decrease
    m_cwnd = m_options.resetCwndToInit ? m_options.initCwnd : m_ssthresh;
  }
}

void
HCSegmentFetcher::signalError(uint32_t code, const std::string& msg)
{
  onError(code, msg);
  stop();
}

void
HCSegmentFetcher::updateRetransmittedSegment(uint64_t segmentNum,
                                           const PendingInterestHandle& pendingInterest,
                                           scheduler::EventId timeoutEvent)
{
  auto pendingSegmentIt = m_pendingSegments.find(segmentNum);
  BOOST_ASSERT(pendingSegmentIt != m_pendingSegments.end());
  BOOST_ASSERT(pendingSegmentIt->second.state == SegmentState::InRetxQueue);
  pendingSegmentIt->second.state = SegmentState::Retransmitted;
  pendingSegmentIt->second.hdl = pendingInterest; // cancels previous pending Interest via scoped handle
  pendingSegmentIt->second.timeoutEvent = timeoutEvent;
}

void
HCSegmentFetcher::cancelExcessInFlightSegments()
{
  for (auto it = m_pendingSegments.begin(); it != m_pendingSegments.end();) {
    if (it->first >= static_cast<uint64_t>(m_nSegments)) {
      it = m_pendingSegments.erase(it); // cancels pending Interest and timeout event
      BOOST_ASSERT(m_nSegmentsInFlight > 0);
      m_nSegmentsInFlight--;
    }
    else {
      ++it;
    }
  }
}

bool
HCSegmentFetcher::checkAllSegmentsReceived()
{
  bool haveReceivedAllSegments = false;

  if (m_nSegments != 0 && m_nReceived >= m_nSegments) {
    haveReceivedAllSegments = true;
    // Verify that all segments in window have been received. If not, send Interests for missing segments.
    for (uint64_t i = 0; i < static_cast<uint64_t>(m_nSegments); i++) {
      if (m_receivedSegments.count(i) == 0) {
        m_retxQueue.push(i);
        haveReceivedAllSegments = false;
      }
    }
  }

  return haveReceivedAllSegments;
}

time::milliseconds
HCSegmentFetcher::getEstimatedRto()
{
  // We don't want an Interest timeout greater than the maximum allowed timeout between the
  // succesful receipt of segments
  return std::min(m_options.maxTimeout,
                  time::duration_cast<time::milliseconds>(m_rttEstimator.getEstimatedRto()));
}

/*
void
SegmentFetcher::afterValidationSuccess(const Data& data, const Interest& origInterest,
                                       std::map<uint64_t, PendingSegment>::iterator pendingSegmentIt,
                                       const weak_ptr<SegmentFetcher>& weakSelf)
{
  if (shouldStop(weakSelf))
    return;

  // We update the last receive time here instead of in the segment received callback so that the
  // transfer will not fail to terminate if we only received invalid Data packets.
  m_timeLastSegmentReceived = time::steady_clock::now();

  m_nReceived++;

  // It was verified in afterSegmentReceivedCb that the last Data name component is a segment number
  uint64_t currentSegment = data.getName().get(-1).toSegment();
  m_receivedSegments.insert(currentSegment);

  // Add measurement to RTO estimator (if not retransmission)
  if (pendingSegmentIt->second.state == SegmentState::FirstInterest) {
    BOOST_ASSERT(m_nSegmentsInFlight >= 0);
    m_rttEstimator.addMeasurement(m_timeLastSegmentReceived - pendingSegmentIt->second.sendTime,
                                  static_cast<size_t>(m_nSegmentsInFlight) + 1);
  }

  // Remove from pending segments map
  m_pendingSegments.erase(pendingSegmentIt);

  // Copy data 
  m_dataBuffer.insert(std::make_pair(currentSegment, data));
  // std::copy(data.wireEncode().value_begin(), data.wireEncode().value_end(),
  //         receivedDataIt.first->second.get()->shared_from_this().get());

  // Copy data in segment to temporary buffer
  auto receivedSegmentIt = m_segmentBuffer.emplace(std::piecewise_construct,
                                                   std::forward_as_tuple(currentSegment),
                                                   std::forward_as_tuple(data.getContent().value_size()));

  std::copy(data.getContent().value_begin(), data.getContent().value_end(),
            receivedSegmentIt.first->second.begin());

  m_nBytesReceived += data.getContent().value_size();
  afterSegmentValidated(data);

  if (data.getFinalBlock()) {
    if (!data.getFinalBlock()->isSegment()) {
      return signalError(FINALBLOCKID_NOT_SEGMENT,
                         "Received FinalBlockId did not contain a segment component");
    }

    if (data.getFinalBlock()->toSegment() + 1 != static_cast<uint64_t>(m_nSegments)) {
      m_nSegments = data.getFinalBlock()->toSegment() + 1;
      cancelExcessInFlightSegments();
    }
  }

  if (m_options.inOrder && m_nextSegmentInOrder == currentSegment) {
    do {
      onInOrderData(std::make_shared<const Buffer>(m_segmentBuffer[m_nextSegmentInOrder]));
      m_dataBuffer.erase(m_nextSegmentInOrder);
      m_segmentBuffer.erase(m_nextSegmentInOrder++);
    } while (m_segmentBuffer.count(m_nextSegmentInOrder) > 0);
  }

  if (m_receivedSegments.size() == 1) {
    m_versionedDataName = data.getName().getPrefix(-1);
    if (currentSegment == 0) {
      // We received the first segment in response, so we can increment the next segment number
      m_nextSegmentNum++;
    }
  }

  if (m_highData < currentSegment) {
    m_highData = currentSegment;
  }

  if (data.getCongestionMark() > 0 && !m_options.ignoreCongMarks) {
    windowDecrease();
  }
  else {
    windowIncrease();
  }

  fetchSegmentsInWindow(origInterest);
}

void
SegmentFetcher::afterValidationFailure(const Data& data,
                                       const security::v2::ValidationError& error,
                                       const weak_ptr<SegmentFetcher>& weakSelf)
{
  if (shouldStop(weakSelf))
    return;

  signalError(SEGMENT_VALIDATION_FAIL, "Segment validation failed: " + boost::lexical_cast<std::string>(error));
}

void
SegmentFetcher::afterNackReceivedCb(const Interest& origInterest, const lp::Nack& nack,
                                    const weak_ptr<SegmentFetcher>& weakSelf)
{
  if (shouldStop(weakSelf))
    return;

  afterSegmentNacked();

  BOOST_ASSERT(m_nSegmentsInFlight > 0);
  m_nSegmentsInFlight--;

  switch (nack.getReason()) {
    case lp::NackReason::DUPLICATE:
    case lp::NackReason::CONGESTION:
      afterNackOrTimeout(origInterest);
      break;
    default:
      signalError(NACK_ERROR, "Nack Error");
      break;
  }
} */

} // namespace util
} // namespace ndn
