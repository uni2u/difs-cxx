#include "ndn-cxx/hash-data.hpp"
#include "ndn-cxx/hash-tlv.hpp"

#include <ndn-cxx/encoding/encoding-buffer.hpp>
#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/mgmt/control-parameters.hpp>
#include <ndn-cxx/name.hpp>

namespace ndn {
  
HashContent&
HashContent::setHash(const ndn::Block& hash)
{
  m_hash = hash;
  m_wire.reset();
  return *this;
}

HashContent&
HashContent::setData(const ndn::Block& data)
{
  m_data = data;
  m_wire.reset();
  return *this;
}

template<ndn::encoding::Tag T>
size_t
HashContent::wireEncode(EncodingImpl<T>& encoder) const
{
  size_t totalLength = 0;
  size_t variableLength = 0;

  variableLength = encoder.prependRange(m_data.value_begin(), m_data.value_end());
  totalLength += variableLength;
  totalLength += encoder.prependVarNumber(variableLength);
  totalLength += encoder.prependVarNumber(tlv::Content);

  variableLength = encoder.prependRange(m_hash.value_begin(), m_hash.value_end());
  totalLength += variableLength;
  totalLength += encoder.prependVarNumber(variableLength);
  totalLength += encoder.prependVarNumber(tlv::NextHash);
  
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::HashContent);
  
  return totalLength;
}

ndn::Block
HashContent::wireEncode() const
{
  if (m_wire.hasWire())
    return m_wire;

  EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  m_wire = buffer.block();
  return m_wire;
}

void
HashContent::wireDecode(const ndn::Block& wire)
{
    m_wire = wire;

    m_wire.parse();
    if (m_wire.type() != ndn::tlv::HashContent)
      BOOST_THROW_EXCEPTION(Error("Requested decoding of HashContent, but Block is of different type"));

    // NextHash
    ndn::Block::element_const_iterator val = m_wire.find(tlv::NextHash);
    if (val != m_wire.elements_end())
    {
      std::tie(std::ignore, m_hash) = ndn::Block::fromBuffer(val->value(), val->value_size());
    }

    // Content
    val = m_wire.find(tlv::Content);
    if (val != m_wire.elements_end())
    {
      std::tie(std::ignore, m_data) = ndn::Block::fromBuffer(val->value(), val->value_size());
    }
}

} // namespace ndn
