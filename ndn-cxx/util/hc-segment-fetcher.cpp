#include <ndn-cxx/util/hc-segment-fetcher.hpp>
#include <iostream>
#include <unistd.h>
#include "ndn-cxx/util/string-helper.hpp"
#include <boost/thread.hpp>

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
  // shared_ptr<HCSegmentFetcher> hc_fetcher(new HCSegmentFetcher(face, validator, options));
  shared_ptr<HCSegmentFetcher> hc_fetcher = std::make_shared<HCSegmentFetcher>(face, validator, options);

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
    m_fetcher->onHashChainComplete.connect([hc_fetcher] (const shared_ptr<std::map<uint64_t, Data>>& dataBufferPtr)
                                         { hc_fetcher->afterHashChainCompleted(dataBufferPtr);
                                         });

  hc_fetcher->m_fetcher = m_fetcher;

  return hc_fetcher;
}

void
printBlock(const Block& block)
{
  std::cout<< "size is :"<< std::dec <<block.value_size() << "printBlock"<<std::endl;
  for(int i = 0; i < block.value_size() + 4; i++) {
    // std::cout <<std::hex<<(unsigned)block.value_begin()[i]<<" ";
    std::cout << std::hex<<(unsigned)block.wire()[i]<<" ";
  }
  std::cout<<std::endl;
}

uint8_t*
copyBlock(const Block& block,int shaper)
{
  uint8_t* new_sig = new uint8_t[32];
  // std::cout<< "size is :"<< std::dec <<block.value_size() <<std::endl;
  memcpy((void*)new_sig, (void*)&(block.wire()[shaper]),32);
  // for(int i = 0; i < block.value_size(); i++) {
  //   // std::cout <<std::hex<<(unsigned)block.value_begin()[i]<<" ";
  //   new_sig[i] = block.wire()[i+shaper];
  //   //std::cout <<std::hex<<(unsigned)block.wire()[i+shaper]<<" ";
  // }
  return new_sig;
}

void
printValues(const uint8_t* values)
{
  std::cout<< "size is :"<< std::dec <<32<<"printValues"<< std::endl;
  for(int i = 0; i < 32; i++) {
    // std::cout <<std::hex<<(unsigned)block.value_begin()[i]<<" ";
    std::cout << std::hex<<(unsigned)values[i]<<" ";
  }
  std::cout<<std::endl;
}

void
HCSegmentFetcher::afterHashChainCompleted(const shared_ptr<std::map<uint64_t, Data>>& dataBufferPtr) {
  std::cout<<"HCSegmentFetcher::afterHashChainCompleted"<<std::endl;
  for (auto const& x : *dataBufferPtr.get())
  {
    auto data = x.second;
    //std::cout<<"HCSegmentFetcher::afterHashChainCompleted"<<data.getContent()<<std::endl;

    Name seqNo = data.getName().getSubName(-1);

    if(data.getSignatureInfo().hasNextHash() && (data.getSignatureType() == tlv::SignatureSha256WithEcdsa || data.getSignatureType() == tlv::SignatureHashChainWithSha256)) {
      int segment = data.getName().get(-1).toSegment();

      auto myblock = data.getSignatureInfo().getNextHash().value();
      uint8_t* signatureNextHash = new uint8_t[32];

      memcpy((void*)signatureNextHash, (void*)&(myblock.wire()[4]),32);

      if (segment != 0) {
        if (segment - 1 == before_segment) {

          // if(before_signature != nullptr && memcmp((void*)data.getSignatureValue().value(), (void*)before_signature->value(), data.getSignatureValue().value_size()+4)) {
          if(before_signature != nullptr && memcmp((void*)(&data.getSignatureValue().wire()[2]), (void*)before_signature, 32)) {
          
            delete[] before_signature;
            onError(HASHCHAIN_ERROR, "Failure hash key error");
            //afterSegmentValidated(data);
          } else {
            //std::cout<< "4"<< std::endl;
            delete[] before_signature;
            //free(signatureBytes);
            success_count++;
            //afterSegmentValidated(data);
          }
        } else {
          //This passes segment when a segment comes not in order.
          //afterSegmentValidated(data);
        }
      } else {
        //This falls for the first segment.
        success_count++;
        //afterSegmentValidated(data);
      }

      int finalBlockId = data.getFinalBlock().value().toSegment();
      if (segment == finalBlockId) {
        //free(before_signature);
        delete[] signatureNextHash;
        if (success_count < finalBlockId / 2) {
          std::cout << "Failure hash key error"<<std::endl;
          std::cout << "success_count:"<<success_count << std::endl;
          std::cout << "segment:"<<segment << std::endl;
          std::cout << "finalBlockId:"<<finalBlockId << std::endl;
          //onError(HASHCHAIN_ERROR, "Failure hash key error");
        }
      }
      //std::cout<< "8"<< std::endl;
      before_segment = segment;
      
      if(signatureNextHash != nullptr) {
        before_signature = signatureNextHash;
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
        //afterSegmentValidated(data);
      }
  }
  
  onHashChainComplete(dataBufferPtr);
}

void 
HCSegmentFetcher::randAfterValidationSuccess(const Data& data) {

  //std::cout<< "randAfterValidationSuccess:"<< data.getSignatureInfo() << std::endl;
  //std::cout<< "randAfterValidationSuccess:"<< data.getSignatureType() << std::endl;
  Name seqNo = data.getName().getSubName(-1);
  //std::cout << "SeqNo:"<< seqNo.toUri() <<std::endl;

  //if(false) {
  //std::cout<< "1"<< std::endl;
  if(data.getSignatureInfo().hasNextHash() && (data.getSignatureType() == tlv::SignatureSha256WithEcdsa || data.getSignatureType() == tlv::SignatureHashChainWithSha256)) {
  int segment = data.getName().get(-1).toSegment();

  auto myblock = data.getSignatureInfo().getNextHash().value();
  uint8_t* signatureNextHash = new uint8_t[32];

  memcpy((void*)signatureNextHash, (void*)&(myblock.wire()[4]),32);

  if (segment != 0) {
    if (segment - 1 == before_segment) {

      // if(before_signature != nullptr && memcmp((void*)data.getSignatureValue().value(), (void*)before_signature->value(), data.getSignatureValue().value_size()+4)) {
      if(before_signature != nullptr && memcmp((void*)(&data.getSignatureValue().wire()[2]), (void*)before_signature, 32)) {
      
        delete[] before_signature;
        onError(HASHCHAIN_ERROR, "Failure hash key error");
        afterSegmentValidated(data);
      } else {
        //std::cout<< "4"<< std::endl;
        delete[] before_signature;
        //free(signatureBytes);
        success_count++;
        afterSegmentValidated(data);
      }
    } else {
      //This passes segment when a segment comes not in order.
      afterSegmentValidated(data);
    }
  } else {
    //This falls for the first segment.
    success_count++;
    afterSegmentValidated(data);
  }

  int finalBlockId = data.getFinalBlock().value().toSegment();
  if (segment == finalBlockId) {
    //free(before_signature);
    delete[] signatureNextHash;
    if (success_count < finalBlockId / 2) {
      std::cout << "Failure hash key error"<<std::endl;
      std::cout << "success_count:"<<success_count << std::endl;
      std::cout << "segment:"<<segment << std::endl;
      std::cout << "finalBlockId:"<<finalBlockId << std::endl;
      //onError(HASHCHAIN_ERROR, "Failure hash key error");
    }
  }
  //std::cout<< "8"<< std::endl;
  before_segment = segment;
  
  if(signatureNextHash != nullptr) {
    before_signature = signatureNextHash;
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