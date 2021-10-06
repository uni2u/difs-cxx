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
#include <ndn-cxx/security/signing-info.hpp>
#include <ndn-cxx/security/signature-sha256-with-rsa.hpp>
#include <chrono>

#include <iostream>
#include <fstream>

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {
class Producer {
  public:
	Producer(std::string name, std::string path) {
		m_name = name;
		m_path = path;
	}

	void enableTestMode() {
		m_test_mode = true;
	}

	void enableVerbose() { m_verbose = true; }

	void disableVerbose() { m_verbose = false; }

	void enableHC() { m_hc = true; }

	void disableHC() { m_hc = false; }

	void setSignerId(std::string id) {
		m_id = id;
	}

	void run() {
		if(m_verbose) {
			std::cout << "Segmentfetcher Producer Start..." << std::endl;
			if(m_hc) {
				std::cout << "Hashchain enabled" << std::endl;
			} else {
				std::cout << "Hashchain disabled" << std::endl;
			}
		}
		prepareData();

		m_face.setInterestFilter(m_name, bind(&Producer::onInterest, this, _1, _2),
		                         nullptr, // RegisterPrefixSuccessCallback is optional
		                         bind(&Producer::onRegisterFailed, this, _1, _2));
		m_face.processEvents();
	}

  private:
	void prepareData() {
		std::ifstream inputFileStream;
		inputFileStream.open(m_path, std::ios::in | std::ios::binary);
		if(!inputFileStream.is_open()) {
			std::cerr << "ERROR: cannot open " << m_path << std::endl;
			exit(-1);
		}

		std::istream& is = inputFileStream;

		int m_blockSize = 8600;
		is.seekg(0, std::ios::beg);
		auto beginPos = is.tellg();
		is.seekg(0, std::ios::end);
		int m_bytes = is.tellg() - beginPos;
		is.seekg(0, std::ios::beg);
		int chunkSize = m_bytes / m_blockSize;
		auto finalBlockId = ndn::name::Component::fromSegment(chunkSize);

		auto m_start = std::chrono::high_resolution_clock::now();

		security::SigningInfo signing_info;
		if(!m_id.empty()) {
			signing_info = security::SigningInfo(security::SigningInfo::SigningInfo::SIGNER_TYPE_ID, "id:" + m_id);
		}

		for(int count = 0; count <= chunkSize; count++) {
			uint8_t* buffer = new uint8_t[m_blockSize];
			is.read(reinterpret_cast<char*>(buffer), m_blockSize);

			auto readSize = is.gcount();

			if(readSize > 0) {
				auto data = std::make_shared<ndn::Data>(Name(m_name).appendSegment(count));
				Block content = ndn::encoding::makeBinaryBlock(tlv::Content, buffer, readSize);
				data->setFreshnessPeriod(3_s);
				data->setContent(content);
				data->setFinalBlock(finalBlockId);

				if(!m_hc) {
					m_keyChain.sign(*data, signing_info);
				}

				m_data.push_back(data);
			} else {
				m_data.clear();
				return;
			}
		}

		inputFileStream.close();

		if(m_hc) {
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

		auto finish = std::chrono::high_resolution_clock::now();

		std::cout << "Preparing Data Completed: " << std::chrono::duration_cast<std::chrono::nanoseconds>(finish - m_start).count() << " ns\n";

		if(m_test_mode)
			exit(0);
	}

	void onInterest(const Name& prefix, const ndn::Interest& interest) {
		uint64_t segmentNo;
		try {
			Name::Component segmentComponent = interest.getName().get(prefix.size());
			if(m_verbose) {
				std::cout << "OnInterest: " << interest.getName() << std::endl;
			}
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
	std::string m_name;
	std::string m_path;
	std::string m_id;

	bool m_verbose = false;
	bool m_hc = false;
	bool m_test_mode = false;

	ndn::HCKeyChain m_hcKeyChain;
	KeyChain m_keyChain;
	std::vector<shared_ptr<ndn::Data>> m_data;
};

} // namespace examples
} // namespace ndn

static int usage(const char* programName) {
	std::cerr << "Usage: " << programName << " [-v] [-h] ndn-name file-path\n"
	          << "\n"
	          << "  -v: be verbose\n"
	          << "  -h: enable HashChain(default: false)\n"
	          << "  -t: enable test mode\n"
	          << "  -s: signing id\n"
	          << "  ndn-name: NDN Name for Data to be written\n"
	          << "  file-path: File path to be read\n"
	          << std::endl;
	return 1;
}

int main(int argc, char** argv) {
	std::string name;
	std::string path;
	bool verbose = false;
	bool hashchain = false;
	bool test_mode = false;
	std::string id;

	int opt;
	while((opt = getopt(argc, argv, "vhts:")) != -1) {
		switch(opt) {
			case 'v':
				verbose = true;
				break;
			case 'h':
				hashchain = true;
				break;
			case 't':
				test_mode = true;
				break;
			case 's':
				id = optarg;
				break;
			default:
				return usage(argv[0]);
		}
	}

	if(optind + 2 != argc) {
		return usage(argv[0]);
	}

	name = argv[optind++];
	path = argv[optind];

	try {
		ndn::examples::Producer producer(name, path);
		if(verbose)
			producer.enableVerbose();

		if(hashchain)
			producer.enableHC();
		
		if(test_mode)
			producer.enableTestMode();
		
		if(!id.empty())
			producer.setSignerId(id);

		producer.run();
		return 0;
	} catch(const std::exception& e) {
		std::cerr << "ERROR: " << e.what() << std::endl;
		return 1;
	}
}
