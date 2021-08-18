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

namespace ndn {
namespace security {
inline namespace v2{
void
HCKeyChain::sign(Data &data, const ndn::Block &nextHash, const SigningInfo &params) {
  auto metaInfo = data.getMetaInfo();
  metaInfo.addAppMetaInfo(nextHash);

  data.setMetaInfo(metaInfo);

  KeyChain::sign(data, params);
}
}
}
}
