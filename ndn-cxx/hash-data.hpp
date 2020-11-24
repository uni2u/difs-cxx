#ifndef HASH_DATA_HPP
#define HASH_DATA_HPP

#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/name.hpp>

namespace ndn {

class HashContent : public ndn::Block
{
public:
  class Error : public ndn::tlv::Error
  {
  public:
    explicit
    Error(const std::string& what)
     : ndn::tlv::Error(what)
    {
    }
  };
  
public:
  
  ndn::Block getHash() const
  {
      return m_hash;
  }
  
  ndn::Block getData() const
  {
      return m_data;
  }
  
  HashContent&
  setHash(const ndn::Block& hash);

  HashContent&
  setData(const ndn::Block& data);
  
  template<ndn::encoding::Tag T>
  size_t
  wireEncode(EncodingImpl<T>& block) const;
  
  ndn::Block
  wireEncode() const;

  void
  wireDecode(const ndn::Block& wire);

private:

  ndn::Block m_hash;
  ndn::Block m_data;

  mutable ndn::Block m_wire;

};

}

#endif  // HASH_DATA_HPP
