
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
#include <ndn-cxx/util/hc-segment-fetcher.hpp>
#include <ndn-cxx/security/validator.hpp>
#include <ndn-cxx/security/validator-config.hpp>
// #include <ndn-cxx/security/validator-null.hpp>

#include <iostream>
#include <fstream>
#include <chrono>

#include <boost/property_tree/info_parser.hpp>

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {

class Consumer {
  public:
	Consumer(std::string& name) { m_name = name; }

	void enableVerbose() { m_verbose = true; }

	void disableVerbose() { m_verbose = false; }

	void enableHC() { m_hc = true; }

	void disableHC() { m_hc = false; }

	void run() {
		ndn::Interest interest(Name(m_name).appendSegment(0));
		boost::chrono::milliseconds lifeTime(3_s);

		interest.setInterestLifetime(lifeTime);
		interest.setMustBeFresh(false);
		if(m_verbose) {
			std::cout << interest << std::endl;
		}

		// ndn::security::ValidatorNull m_validator;
		std::string configPath = "node.conf";

		std::ifstream fin(configPath.c_str());
		if(!fin.is_open())
			std::cout << "open error" << std::endl;

		using namespace boost::property_tree;
		ptree propertyTree;
		try {
			read_info(fin, propertyTree);
		} catch(const ptree_error& e) { std::cout << "failed to read configuration file '" + configPath + "'" << std::endl; }

		ptree repoConf = propertyTree.get_child("repo");

		boost::property_tree::ptree m_validatorNode;
		ndn::security::ValidatorConfig m_validatorConfig(m_face);
		m_validatorNode = repoConf.get_child("validator");
		m_validatorConfig.load(m_validatorNode, configPath);
		// ndn::security::Validator m_validator;
		ndn::security::Validator& m_validator(m_validatorConfig);

		ndn::util::SegmentFetcher::Options options;
		options.initCwnd = 12;
		options.interestLifetime = lifeTime;
		options.maxTimeout = lifeTime;

		m_start = std::chrono::high_resolution_clock::now();

		if(m_hc) {
			std::shared_ptr<ndn::util::HCSegmentFetcher> hc_fetcher;
			auto hcFetcher = hc_fetcher->start(m_face, interest, m_validator, options);
			hcFetcher->onError.connect([this, hcFetcher](uint32_t errorCode, const std::string& errorMsg) { onError(errorMsg); });
			hcFetcher->afterSegmentValidated.connect([this, hcFetcher](const Data& data) { onData(data); });
			hcFetcher->afterSegmentTimedOut.connect([this, hcFetcher]() { onTimeout(*hcFetcher); });
			hcFetcher->onComplete.connect([this, hcFetcher](const ndn::ConstBufferPtr& ptr) { onComplete(ptr); });

			m_face.processEvents();
		} else {
			std::shared_ptr<ndn::util::SegmentFetcher> fetcher;
			auto Fetcher = fetcher->start(m_face, interest, m_validator, options);
			Fetcher->onError.connect([this, Fetcher](uint32_t errorCode, const std::string& errorMsg) { onError(errorMsg); });
			Fetcher->afterSegmentValidated.connect([this, Fetcher](const Data& data) { onData(data); });
			Fetcher->afterSegmentTimedOut.connect([this, Fetcher]() { onTimeout(*Fetcher); });
			Fetcher->onComplete.connect([this, Fetcher](const ndn::ConstBufferPtr& ptr) { onComplete(ptr); });

			m_face.processEvents();
		}
	}

  private:
	Face m_face;
	bool m_verbose = false;
	bool m_hc = false;
	std::string m_name;
	std::chrono::_V2::system_clock::time_point m_start;

	void onData(const Data& data) const {
		if(m_verbose) {
			auto content = data.getContent();
			std::string msg = reinterpret_cast<const char*>(content.value());
			msg = msg.substr(0, content.value_size());
			std::cout << msg;
		}
	}

	void onTimeout(ndn::util::HCSegmentFetcher& hc_fetcher) const {
		if(m_verbose)
			std::cout << "Timeout" << std::endl;
	}

	void onTimeout(ndn::util::SegmentFetcher& fetcher) const {
		if(m_verbose)
			std::cout << "Timeout" << std::endl;
	}

	void onComplete(const ndn::ConstBufferPtr& ptr) const {
		auto finish = std::chrono::high_resolution_clock::now();
		std::cout << "Complete: " << std::chrono::duration_cast<std::chrono::nanoseconds>(finish - m_start).count() << " ns\n";
	}

	void onError(const std::string& errorMsg) { std::cout << "Error: " << errorMsg << std::endl; }
};

} // namespace examples
} // namespace ndn

static int usage(const char* programName) {
	std::cerr << "Usage: " << programName << " [-v] [-h] ndn-name\n"
	          << "\n"
	          << "  -v: be verbose\n"
	          << "  -h: Check HashChain(default: false)\n"
	          << "  ndn-name: NDN Name prefix for Data to be read\n"
	          << std::endl;
	return 1;
}

int main(int argc, char** argv) {
	std::string name;
	bool verbose = false;
	bool hashchain = false;

	int opt;
	while((opt = getopt(argc, argv, "vh")) != -1) {
		switch(opt) {
			case 'v':
				verbose = true;
				break;
			case 'h':
				hashchain = true;
				break;
			default:
				return usage(argv[0]);
		}
	}

	if(optind + 1 != argc) {
		return usage(argv[0]);
	}

	name = argv[optind];

	try {
		ndn::examples::Consumer consumer(name);
		if(verbose)
			consumer.enableVerbose();
		else
			consumer.disableVerbose();

		if(hashchain)
			consumer.enableHC();
		else
			consumer.disableHC();

		consumer.run();
		return 0;
	} catch(const std::exception& e) {
		std::cerr << "ERROR: " << e.what() << std::endl;
		return 1;
	}
}
