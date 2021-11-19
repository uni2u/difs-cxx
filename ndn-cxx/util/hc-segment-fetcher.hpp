/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2020 Regents of the University of California.
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
#ifndef NDN_UTIL_HC_SEGMENT_FETCHER_HPP
#define NDN_UTIL_HC_SEGMENT_FETCHER_HPP

#include "ndn-cxx/util/segment-fetcher.hpp"

#include "ndn-cxx/face.hpp"
#include "ndn-cxx/security/validator.hpp"
#include "ndn-cxx/util/rtt-estimator.hpp"
#include "ndn-cxx/util/scheduler.hpp"
#include "ndn-cxx/util/signal.hpp"


namespace ndn {
namespace util {
class HCSegmentFetcher
{
public:
  enum ErrorCode {
    /// Retrieval timed out because the maximum timeout between the successful receipt of segments was exceeded
    INTEREST_TIMEOUT = 1,
    /// One of the retrieved Data packets lacked a segment number in the last Name component (excl. implicit digest)
    DATA_HAS_NO_SEGMENT = 2,
    /// One of the retrieved segments failed user-provided validation
    SEGMENT_VALIDATION_FAIL = 3,
    /// An unrecoverable Nack was received during retrieval
    NACK_ERROR = 4,
    /// A received FinalBlockId did not contain a segment component
    FINALBLOCKID_NOT_SEGMENT = 5,
    // HashChain signature value error
    HASHCHAIN_ERROR = 6,
  };

  shared_ptr<HCSegmentFetcher>
  start(Face &face,
      const Interest &baseInterest,
      security::v2::Validator &validator,
      const SegmentFetcher::Options &options);

  void
  stop();

private:
  HCSegmentFetcher(Face& face, security::v2::Validator& validator, const SegmentFetcher::Options& options);

  void 
  afterValidationSuccess(const Data &data);

  void
  randAfterValidationSuccess(const Data &data);

public:
  shared_ptr<SegmentFetcher> m_fetcher;

public:
  Signal<HCSegmentFetcher, ConstBufferPtr> onComplete;
  Signal<HCSegmentFetcher, Data> afterSegmentReceived;
  Signal<HCSegmentFetcher> afterSegmentNacked;
  Signal<HCSegmentFetcher, ConstBufferPtr> onInOrderData;
  Signal<HCSegmentFetcher> onInOrderComplete;
  Signal<HCSegmentFetcher, Data> afterSegmentValidated;
  Signal<HCSegmentFetcher> afterSegmentTimedOut;
  Signal<HCSegmentFetcher, uint32_t, std::string> onError;

private:
  std::map<int, std::shared_ptr<Block>> nextHash_map;
  std::map<int, std::shared_ptr<Data>> data_map;
  uint8_t* before_signature;
  int before_segment;
  int success_count;
}; 

}
}

#endif

