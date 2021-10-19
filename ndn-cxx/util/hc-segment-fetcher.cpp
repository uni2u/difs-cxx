#include <ndn-cxx/util/hc-segment-fetcher.hpp>
#include <iostream>
#include <unistd.h>
#include <string.h>
#include "ndn-cxx/util/string-helper.hpp"
#include "ndn-cxx/util/logger.hpp"

namespace ndn {
namespace util {

NDN_LOG_INIT(ndn.util.HCSegmentFetcher);

HCSegmentFetcher::HCSegmentFetcher(Face& face, security::v2::Validator& validator, const SegmentFetcher::Options& options) {

}

shared_ptr<HCSegmentFetcher>
HCSegmentFetcher::start(Face &face,
    const Interest &baseInterest,
    security::v2::Validator &validator,
    const SegmentFetcher::Options &options)
{
  shared_ptr<HCSegmentFetcher> hc_fetcher(new HCSegmentFetcher(face, validator, options));

  auto m_fetcher = SegmentFetcher::start(face, baseInterest, validator, options);
  m_fetcher->onComplete.connect([hc_fetcher] (const ConstBufferPtr& buffer)
                                         { hc_fetcher->onComplete(buffer);
                                         });

  m_fetcher->afterSegmentReceived.connect([hc_fetcher] (const Data& data)
                                         { hc_fetcher->afterSegmentReceived(data);
                                         });

  m_fetcher->afterSegmentNacked.connect([hc_fetcher] ()
                                         { hc_fetcher->afterSegmentNacked();
                                         });

  m_fetcher->onInOrderData.connect([hc_fetcher] (const ConstBufferPtr& buffer)
                                         { hc_fetcher->onInOrderData(buffer);
                                         });

  m_fetcher->onInOrderComplete.connect([hc_fetcher] ()
                                         { hc_fetcher->onInOrderComplete();
                                         });

  m_fetcher->afterSegmentValidated.connect([hc_fetcher] (const Data& data)
                                         { hc_fetcher->randAfterValidationSuccess(data);
                                         });

  m_fetcher->afterSegmentTimedOut.connect([hc_fetcher] ()
                                         { hc_fetcher->afterSegmentTimedOut();
                                         });

  m_fetcher->onError.connect([hc_fetcher] (uint32_t errorCode, const std::string& errorMsg)
                                         { hc_fetcher->onError(errorCode, errorMsg);
                                         });

  hc_fetcher->m_fetcher = m_fetcher;

  return hc_fetcher;
}

// void
// HCSegmentFetcher::afterValidationSuccess(const Data& data) {
//   int segment_no = data.getName().get(-1).toSegment();
//   auto content = data.getContent();
//   content.parse();

//   if(data_map.size() != 0 && data_map.find(segment_no+1)->second != 0) {
//     auto cData = data_map.find(segment_no+1)->second;
//     auto m_content = cData->getContent();
//     m_content.parse();
//     auto hash_block = m_content.get(tlv::SignatureValue);
//     if (memcmp((void*)content.get(tlv::SignatureValue).value(), (void*)hash_block.value(), data.getSignatureValue().value_size())) {
//       onError(HASHCHAIN_ERROR, "Failure hash key error");
//     } else {
//       data_map.erase(segment_no+1);
//       afterSegmentValidated(data);
//     }
//   } else {
//     for (auto iter = content.elements_begin(); iter != content.elements_end(); iter++) {
//       if(iter->type() == tlv::SignatureValue) {
//         auto signature_block = iter.base();
//         std::shared_ptr<Block> block = std::make_shared<Block>(*signature_block); 
//         nextHash_map.insert(std::pair<int, std::shared_ptr<Block>>(segment_no, block));
//       }
//     }
//   }

//   if(segment_no != 0){
//     auto hash_block = nextHash_map.find(segment_no-1)->second;
//     if(hash_block == 0) {
//       std::shared_ptr<Data> m_data = std::make_shared<Data>(data); 
//       data_map.insert(std::pair<int, std::shared_ptr<Data>>(segment_no, m_data));
//     } else if (memcmp((void*)data.getSignatureValue().value(), (void*)hash_block->value(), data.getSignatureValue().value_size())) {
//       onError(HASHCHAIN_ERROR, "Failure hash key error");
//     } else {
//       data_map.erase(segment_no-1);
//       afterSegmentValidated(data);
//     }
//   } else {
//     afterSegmentValidated(data);
//   }
// }
void
printBlock(const Block& block)
{
  NDN_LOG_DEBUG("size is :"<< std::dec <<block.value_size());
  std::ostringstream next_hash_str;
  for(int i = 4; i < block.value_size()+4; i++) {
    next_hash_str<<std::hex<<(unsigned)block.wire()[i]<<" ";
  }
  NDN_LOG_DEBUG(next_hash_str.str());
}

void 
HCSegmentFetcher::randAfterValidationSuccess(const Data& data) {

  NDN_LOG_TRACE("randAfterValidationSuccess: "<< data.getSignatureInfo() << " " << data.getSignatureType());
  Name seqNo = data.getName().getSubName(-1);
  NDN_LOG_DEBUG("SeqNo: " << seqNo.toUri());

  if(data.getSignatureType() == tlv::SignatureHashChainWithEcdsa || data.getSignatureType() == tlv::SignatureHashChainWithSha256) {
    int segment = data.getName().get(-1).toSegment();

    NDN_LOG_DEBUG("before_segment: "<<before_segment);
    if (segment != 0) {
      if (segment - 1 == before_segment) {
        NDN_LOG_DEBUG("Ordered data segment");
        if(before_signature != nullptr && memcmp((void*)data.getSignatureValue().value(), (void*)before_signature->value(), data.getSignatureValue().value_size())) {
          NDN_LOG_DEBUG("Wrong hash key");
          onError(HASHCHAIN_ERROR, "Failure hash key error");
        } else {
          NDN_LOG_DEBUG("Correct hash key");
          success_count++;
          afterSegmentValidated(data);
        }
      } else {
        NDN_LOG_DEBUG("Disordered data segment");
        afterSegmentValidated(data);
      }
    } else {
      NDN_LOG_DEBUG("First segment data");
      success_count++;
      afterSegmentValidated(data);
    }

    NDN_LOG_TRACE("randAfterValidationSuccess::6");
    int finalBlockId = data.getFinalBlock().value().toSegment();
    if (segment == finalBlockId) {
      if (success_count < finalBlockId / 2) {
        onError(HASHCHAIN_ERROR, "Failure hash key error");
      }
    }
    NDN_LOG_TRACE("randAfterValidationSuccess::7");
    
    before_segment = segment;

    optional<Block> previousHash = data.getSignatureInfo().getNextHash();
    NDN_LOG_DEBUG("---getnexthash----: "<< data.getSignatureType());
    if(previousHash != nullopt) {
      before_signature = std::make_shared<Block>(previousHash.value());
      NDN_LOG_TRACE("randAfterValidationSuccess::8");
      printBlock(data.getSignatureInfo().getNextHash().value());
    } else {
      before_signature = nullptr;
      NDN_LOG_TRACE("randAfterValidationSuccess::9");
    }
  } else {
    NDN_LOG_TRACE("randAfterValidationSuccess::11");
    afterSegmentValidated(data);
  }
}

void
HCSegmentFetcher::stop() {
  if (!m_fetcher) {
    return;
  }

  m_fetcher->stop();
}
}
}