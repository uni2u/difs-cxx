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

#include <iostream>
#include <algorithm>

#include "ndn-cxx/security/hc-key-chain.hpp"

#include "ndn-cxx/interest.hpp"
#include "ndn-cxx/security/certificate.hpp"
#include "ndn-cxx/security/key-params.hpp"
#include "ndn-cxx/security/pib/pib.hpp"
#include "ndn-cxx/security/safe-bag.hpp"
#include "ndn-cxx/security/signing-info.hpp"
#include "ndn-cxx/security/tpm/tpm.hpp"
#include "ndn-cxx/util/logger.hpp"
#include <ndn-cxx/util/segment-fetcher.hpp>
#include "ndn-cxx/security/signing-helpers.hpp"

namespace ndn {
namespace security {


inline namespace v2{

NDN_LOG_INIT(ndn.security.HCKeyChain);

void
printBlock(const Block& block)
{
  NDN_LOG_DEBUG("size is :"<< std::dec <<block.value_size());
  for(int i = 0; i < block.value_size(); i++) {
    NDN_LOG_DEBUG(std::hex<<(unsigned)block.wire()[i]<<" ");
  }
}

std::vector<shared_ptr<Data>>
HCKeyChain::makeHashChain(const ndn::Name m_versionedPrefix, std::istream& is, const Options& options){

  std::vector<shared_ptr<Data>> m_store;

  time::milliseconds freshnessPeriod{10000};

  BOOST_ASSERT(m_store.empty());


  std::vector<uint8_t> buffer(options.maxSegmentSize - 32);
  while (is.good()) {
    is.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    const auto nCharsRead = is.gcount();

    if (nCharsRead > 0) {
      auto data = make_shared<Data>(Name(m_versionedPrefix).appendSegment(m_store.size()));
      data->setFreshnessPeriod(freshnessPeriod);
      data->setContent(buffer.data(), static_cast<size_t>(nCharsRead));
      m_store.push_back(data);
    }
  }

  if (m_store.empty()) {
    auto data = make_shared<Data>(Name(m_versionedPrefix).appendSegment(0));
    data->setFreshnessPeriod(freshnessPeriod);
    m_store.push_back(data);
  }

  auto finalBlockId = name::Component::fromSegment(m_store.size() - 1);
  // for (const auto& data : m_store) {
  static uint8_t zeros[32] = {0,0,0,0,0,0,0,0,0,0,
                      0,0,0,0,0,0,0,0,0,0,
                      0,0,0,0,0,0,0,0,0,0,
                      0,0};

  Block nextHash = ndn::encoding::makeBinaryBlock(tlv::NextHashValue, zeros, 32);
  Name tmp = Name(options.signingInfo.getSignerName());

  for (auto it = m_store.rbegin(); it != m_store.rend(); it++) {
    Data& data = **it;
    data.setFinalBlock(finalBlockId);
    if (it == m_store.rend() - 1 /* First block */) {
      sign(data, nextHash, ndn::signingByHashChainIdentity(tmp));
    } else {
      sign(data, nextHash, ndn::security::SigningInfo(ndn::security::SigningInfo::SIGNER_TYPE_HASHCHAIN_SHA256));
    }
    // std::cout << "data.content type: " << data.getContent().type() << std::endl;
    nextHash = ndn::encoding::makeBinaryBlock(tlv::NextHashValue, data.getSignatureValue().value(), data.getSignatureValue().value_size());
  }

  return m_store;

}

std::vector<shared_ptr<Data>>
HCKeyChain::makeSignedData(const ndn::Name m_versionedPrefix, std::istream& is, const Options& options){

  std::vector<shared_ptr<Data>> m_store;

  time::milliseconds freshnessPeriod{10000};

  BOOST_ASSERT(m_store.empty());


  std::vector<uint8_t> buffer(options.maxSegmentSize - 32);
  while (is.good()) {
    is.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    const auto nCharsRead = is.gcount();

    if (nCharsRead > 0) {
      auto data = make_shared<Data>(Name(m_versionedPrefix).appendSegment(m_store.size()));
      data->setFreshnessPeriod(freshnessPeriod);
      data->setContent(buffer.data(), static_cast<size_t>(nCharsRead));
      m_store.push_back(data);
    }
  }

  if (m_store.empty()) {
    auto data = make_shared<Data>(Name(m_versionedPrefix).appendSegment(0));
    data->setFreshnessPeriod(freshnessPeriod);
    m_store.push_back(data);
  }

  auto finalBlockId = name::Component::fromSegment(m_store.size() - 1);

  Name tmp = Name(options.signingInfo.getSignerName());

  for (auto it = m_store.rbegin(); it != m_store.rend(); it++) {
    Data& data = **it;
    data.setFinalBlock(finalBlockId);
    if (it == m_store.rend() - 1 /* First block */) {
      sign(data, ndn::signingByIdentity(tmp));
    } else {
      sign(data, ndn::signingByIdentity(tmp));
    }
  }

  return m_store;

}

void
HCKeyChain::sign(Data &data, const ndn::Block &nextHash, const SigningInfo &params) {
  NDN_LOG_INFO("HCKeyChain::sign");
  NDN_LOG_DEBUG("HCKeyChain::sign:"<<params.getSignerType()<<params.getSignerName().toUri());
  printBlock(nextHash);
  auto signatureInfo = data.getSignatureInfo();
  signatureInfo.setNextHash(nextHash);

  data.setSignatureInfo(signatureInfo);

  KeyChain::sign(data, params);
}
void
HCKeyChain::sign(Data &data, const SigningInfo &params) {
  KeyChain::sign(data, params);
}
}
}
}