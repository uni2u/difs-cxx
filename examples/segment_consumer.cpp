
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
#include <ndn-cxx/security/validator-null.hpp>

#include <iostream>

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {

class Consumer {
  public:
	void run() {
		ndn::Interest interest(Name("/example/testApp/randomData").appendSegment(0));
		boost::chrono::milliseconds lifeTime(3_s);
		interest.setInterestLifetime(lifeTime);
		interest.setMustBeFresh(false);
		std::cout << interest << std::endl;

		ndn::security::ValidatorNull m_validator;

		ndn::util::SegmentFetcher::Options options;
		options.initCwnd = 12;
		options.interestLifetime = lifeTime;
		options.maxTimeout = lifeTime;

		std::shared_ptr<ndn::util::HCSegmentFetcher> hc_fetcher;
		auto hcFetcher = hc_fetcher->start(m_face, interest, m_validator, options);
		hcFetcher->onError.connect([](uint32_t errorCode, const std::string& errorMsg) { std::cout << "Error: " << errorMsg << std::endl; });
		hcFetcher->afterSegmentValidated.connect([this, hcFetcher](const Data& data) { onData(data); });
		hcFetcher->afterSegmentTimedOut.connect([this, hcFetcher]() { onTimeout(*hcFetcher); });
		m_face.processEvents();
	}

  private:
	Face m_face;

	void onData(const Data& data) const {
		std::cout << "Received Data " << data << std::endl;
		auto content = data.getContent();
		std::string msg = reinterpret_cast<const char*>(content.value());
		msg = msg.substr(0, content.value_size());
		std::cout << msg;
	}

	void onTimeout(ndn::util::HCSegmentFetcher& hc_fetcher) const {
		//     std::cout << "Timeout for " << interest << std::endl;
	}
};

} // namespace examples
} // namespace ndn

int main(int argc, char** argv) {
	try {
		ndn::examples::Consumer consumer;
		consumer.run();
		return 0;
	} catch(const std::exception& e) {
		std::cerr << "ERROR: " << e.what() << std::endl;
		return 1;
	}
}
