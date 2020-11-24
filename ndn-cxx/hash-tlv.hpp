#ifndef HASH_TLV_HPP
#define HASH_TLV_HPP

#include <ndn-cxx/encoding/tlv.hpp>

namespace ndn {
namespace tlv {
    
using namespace ndn::tlv;

enum {
    HashContent = 900,
    NextHash = 901,
    // RealContent = 902,
};

}
}

#endif // HASH_TLV_HPP
