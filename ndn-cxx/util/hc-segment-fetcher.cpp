#include <ndn-cxx/util/hc-segment-fetcher.hpp>
#include <iostream>
#include <unistd.h>
#include "ndn-cxx/util/string-helper.hpp"

namespace ndn {
namespace util {

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
  std::cout<< "size is :"<< std::dec <<block.value_size() << std::endl;
  for(int i = 0; i < block.value_size(); i++) {
    std::cout <<std::hex<<(unsigned)block.wire()[i]<<" ";
  }
  std::cout<<std::endl;
}


void 
HCSegmentFetcher::randAfterValidationSuccess(const Data& data) {

  //std::cout<< "randAfterValidationSuccess:"<< data.getSignatureInfo() << std::endl;
  //std::cout<< "randAfterValidationSuccess:"<< data.getSignatureType() << std::endl;
  Name seqNo = data.getName().getSubName(-1);
  //std::cout << "SeqNo:"<< seqNo.toUri() <<std::endl;

  //if(false) {
  //std::cout<< "1"<< std::endl;
  if(data.getSignatureType() == tlv::SignatureSha256WithEcdsa || data.getSignatureType() == tlv::SignatureHashChainWithSha256) {
  int segment = data.getName().get(-1).toSegment();

  //std::cout<< "before_segment"<<before_segment<< std::endl;
  if (segment != 0) {
    if (segment - 1 == before_segment) {
      //std::cout<< "3"<< std::endl;
      if(before_signature != nullptr && memcmp((void*)data.getSignatureValue().value(), (void*)before_signature->value(), data.getSignatureValue().value_size())) {
        //std::cout<< "3.1"<< std::endl;
        //onError(HASHCHAIN_ERROR, "Failure hash key error");
        afterSegmentValidated(data);
      } else {
        //std::cout<< "4"<< std::endl;
        success_count++;
        afterSegmentValidated(data);
      }
    } else {
      //std::cout<< "5"<< std::endl;
      afterSegmentValidated(data);
    }
  } else {
    //std::cout<< "6"<< std::endl;
    success_count++;
    afterSegmentValidated(data);
  }

  //std::cout<< "7"<< std::endl;
  int finalBlockId = data.getFinalBlock().value().toSegment();
  if (segment == finalBlockId) {
    if (success_count < finalBlockId / 2) {
      onError(HASHCHAIN_ERROR, "Failure hash key error");
    }
  }
  //std::cout<< "8"<< std::endl;
  
  before_segment = segment;
  optional<Block> previousHash = data.getSignatureInfo().getNextHash();
  //std::cout<< "---getnexthash----: "<< data.getSignatureType()<<std::endl;
  if(previousHash != nullopt) {
    before_signature = std::make_shared<Block>(previousHash.value());
    //std::cout<< "previousHash: "<< std::endl;
    //printBlock(data.getSignatureInfo().getNextHash().value());
  } else {
    before_signature = nullptr;
    //std::cout<< "previousHash: nullopt "<< std::endl;
  }
  //std::cout<< "9"<< std::endl;
  //before_signature = std::make_shared<Block>(data.getMetaInfo().getAppMetaInfo().front());
  } 
  else {
    //std::cout<< "else "<< std::endl;
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