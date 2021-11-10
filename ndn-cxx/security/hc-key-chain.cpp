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

void
HCKeyChain::sign(Data &data, const ndn::Block &nextHash, const SigningInfo &params) {
  NDN_LOG_INFO("HCKeyChain::sign");
  NDN_LOG_DEBUG("HCKeyChain::sign:"<<params.getSignerType()<<params.getSignerName().toUri());
  printBlock(nextHash);
  auto signatureInfo = data.getSignatureInfo();
  signatureInfo.setNextHash(nextHash);
  //if(signatureInfo.getSignatureType() == ndn::tlv::SignatureHashChainWithSha256) {
  //  NDN_LOG_DEBUG("HCKeyChain::sign SignatureHashChainWithSha256");
  //  signatureInfo.setKeyLocator(Name("/localhost/identity/digest-sha256"));
  //} else {
  //  pib::Identity identity;
    // identity = params.getPibIdentity();
    // pib::Key key = identity.getDefaultKey();
  //  signatureInfo.setKeyLocator(Name("example/repo/KEY/%E3~a%18%CB%25%04%B2"));
  //   NDN_LOG_DEBUG("HCKeyChain::sign NOT SignatureHashChainWithSha256");
  //}
  // signatureInfo.setTime(time::system_clock::time_point(1590169108480_ms));
  // optional<time::system_clock::time_point> tmp = signatureInfo.getTime();
  // if(tmp != nullopt) {
  //   std::cout<<"getTime"<< tmp.value().time_since_epoch().count() <<std::endl;
  // } else {
  //   std::cout<<"gettime null"<<std::endl;
  //}
  // auto metaInfo = data.getMetaInfo();
  // metaInfo.addAppMetaInfo(nextHash);

  // data.setMetaInfo(metaInfo);
  data.setSignatureInfo(signatureInfo);
  // std::cout<<"second:"<<std::endl;
  // printBlock(data.getSignatureInfo().getNextHash().value());

  KeyChain::sign(data, params);
}
void
HCKeyChain::sign(Data &data, const SigningInfo &params) {
  KeyChain::sign(data, params);
}
}
}
}