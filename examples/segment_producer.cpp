/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2019 Regents of the University of California.
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
 *
 * @author Alexander Afanasyev <http://lasr.cs.ucla.edu/afanasyev/index.html>
 */

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/hc-key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

#include <iostream>

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {
class Producer {
  public:
	void run(std::istream* is) {
		prepareData("/example/testApp/randomData", *is, true);

		m_face.setInterestFilter("/example/testApp/randomData", bind(&Producer::onInterest, this, _1, _2),
		                         nullptr, // RegisterPrefixSuccessCallback is optional
		                         bind(&Producer::onRegisterFailed, this, _1, _2));
		m_face.processEvents();
	}

  private:
	void prepareData(const std::string dataPrefix, std::istream& is, bool enable_haschain) {
		int m_blockSize = 8600;
		is.seekg(0, std::ios::beg);
		auto beginPos = is.tellg();
		is.seekg(0, std::ios::end);
		int m_bytes = is.tellg() - beginPos;
		is.seekg(0, std::ios::beg);
		int chunkSize = m_bytes / m_blockSize;
		auto finalBlockId = ndn::name::Component::fromSegment(chunkSize);

		for(int count = 0; count <= chunkSize; count++) {
			uint8_t* buffer = new uint8_t[m_blockSize];
			is.read(reinterpret_cast<char*>(buffer), m_blockSize);

			auto readSize = is.gcount();

			if(readSize > 0) {
				auto data = std::make_shared<ndn::Data>(Name(dataPrefix).appendSegment(count));
				Block content = ndn::encoding::makeBinaryBlock(tlv::Content, buffer, readSize);
				data->setFreshnessPeriod(3_s);
				data->setContent(content);
				data->setFinalBlock(finalBlockId);

				m_data.push_back(data);
			} else {
				m_data.clear();
				return;
			}
		}

		Block nextHash(ndn::lp::tlv::HashChain);

		for(auto iter = m_data.rbegin(); iter != m_data.rend(); iter++) {
			if(iter == m_data.rend()) {
				m_hcKeyChain.sign(**iter, nextHash);
			} else {
				m_hcKeyChain.sign(**iter, nextHash, ndn::signingWithHashChainSha256());
			}

			nextHash = ndn::encoding::makeBinaryBlock(ndn::lp::tlv::HashChain, (*iter)->getSignatureValue().value(), (*iter)->getSignatureValue().value_size());
		}
	}

	void onInterest(const Name& prefix, const ndn::Interest& interest) {
		uint64_t segmentNo;
		try {
			Name::Component segmentComponent = interest.getName().get(prefix.size());
			std::cout << prefix << std::endl;
			std::cout << segmentComponent << std::endl;
			segmentNo = segmentComponent.toSegment();
		} catch(const tlv::Error& e) {
			std::cout << "failed" << std::endl;
			return;
		}

		shared_ptr<Data> data;
		if(segmentNo < m_data.size()) {
			data = m_data[segmentNo];
		} else if(interest.matchesData(*m_data[0])) {
			data = m_data[0];
		}

		if(data != nullptr) {
			m_face.put(*data);
		} else {
			m_face.put(ndn::lp::Nack(interest));
		}
	}

	void onRegisterFailed(const Name& prefix, const std::string& reason) {
		std::cerr << "ERROR: Failed to register prefix '" << prefix << "' with the local forwarder (" << reason << ")" << std::endl;
		m_face.shutdown();
	}

  private:
	Face m_face;
	ndn::HCKeyChain m_hcKeyChain;
	std::vector<shared_ptr<ndn::Data>> m_data;
};

} // namespace examples
} // namespace ndn

#include <iostream>
#include <fstream>

int main(int argc, char** argv) {
	std::ifstream inputFileStream;
	std::istream* insertStream;

	if(strcmp(argv[1], "-") == 0) {
		insertStream = &std::cin;
	} else {
		inputFileStream.open(argv[1], std::ios::in | std::ios::binary);
		if(!inputFileStream.is_open()) {
			std::cerr << "ERROR: cannot open " << argv[3] << std::endl;
			return 2;
		}

		insertStream = &inputFileStream;
	}

	try {
		ndn::examples::Producer producer;
		producer.run(insertStream);
		return 0;
	} catch(const std::exception& e) {
		std::cerr << "ERROR: " << e.what() << std::endl;
		return 1;
	}
}
