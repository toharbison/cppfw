#include <list>
#include "../firewall.hpp"
#include "quickcheck/quickcheck.hh"

using namespace quickcheck;

class AddrtypeSetSrc : public Property<unsigned short, bool> {
  bool accepts(const unsigned short& x, const bool& y){
    return x < (1 << 12) && x > 0;
  }
  bool holdsFor(const unsigned short& x, const bool& y){
    AddrtypeMatch match;
    match.setSrc(x, y);
    xt_addrtype_match* specs = (xt_addrtype_match*)match.getSpecs();
    return specs->source == x && !(specs->flags ^ y);
  }
};

class AddrtypeSetDst : public Property<unsigned short, bool> {
  bool accepts(const unsigned short& x, const bool& y){
    return x < (1 << 12) && x > 0;
  }
  bool holdsFor(const unsigned short& x, const bool& y){
    AddrtypeMatch match;
    match.setDst(x, y);
    xt_addrtype_match* specs = (xt_addrtype_match*)match.getSpecs();
    return specs->dest == x && !((specs->flags >> 1) ^ y);
  }
};

class AddrtypeLimitIFace : public Property<bool> {
  bool holdsFor(const bool& x){
    AddrtypeMatch match;
    match.limitIFace();
    xt_addrtype_match* specs = (xt_addrtype_match*)match.getSpecs();
    return specs->flags == XT_ADDRTYPE_LIMIT_IFACE_IN;
  }
};

class AddrtypeLimitOFace : public Property<bool> {
  bool holdsFor(const bool& x){
    AddrtypeMatch match;
    match.limitOFace();
    xt_addrtype_match* specs = (xt_addrtype_match*)match.getSpecs();
    return specs->flags == XT_ADDRTYPE_LIMIT_IFACE_OUT;
  }
};

template<class T>
class JsonTest : public Property<bool>{
  bool holdsFor(const bool& x){
    T t1;
    json j = t1.asJson();
    T t2(j);
    return memcmp(&t1, &t2, sizeof(T)) == 0;    
  }
};

int main(){
  check<AddrtypeSetSrc>("Addrtype::setSrc");
  check<AddrtypeSetDst>("Addrtype::setDst");
  check<AddrtypeLimitIFace>("Addrtype::limitIFace");
  check<AddrtypeLimitOFace>("Addrtype::limitOFace");
  check<JsonTest<AddrtypeMatch>>("AddrtypeMatch to and from json functions");
  check<JsonTest<BpfMatch>>("BpfMatch to and from json functions");
  check<JsonTest<CgroupMatch>>("CgroupMatch to and from json functions");
  check<JsonTest<ClusterMatch>>("ClusterMatch to and from json functions");
  check<JsonTest<CommentMatch>>("CommentMatch to and from json functions");
  check<JsonTest<TcpMatch>>("TcpMatch to and from json functions");
  check<JsonTest<UdpMatch>>("UdpMatch to and from json functions");
  check<JsonTest<Icmp4Match>>("Icmp4Match to and from json functions");
  check<JsonTest<Icmp6Match>>("Icmp6Match to and from json functions");
  check<JsonTest<AuditTarget>>("AuditTarget to and from json works");
  check<JsonTest<ChecksumTarget>>("ChecksumTarget to and from json works");
  check<JsonTest<ConnmarkTarget>>("ConnmarkTarget to and from json works");
  check<JsonTest<ConnsecmarkTarget>>("ConnsecmarkTarget to and from json works");
  check<JsonTest<CTTarget>>("CTTarget to and from json works");
  check<JsonTest<DscpTarget>>("DscpTarget to and from json works");
  check<JsonTest<TosTarget>>("TosTarget to and from json works");
  check<JsonTest<HmarkTarget>>("HmarkTarget to and from json works");
  check<JsonTest<IdletimerTarget>>("IdletimerTarget to and from json works");
  check<JsonTest<LedTarget>>("LedTarget to and from json works");
  check<JsonTest<LogTarget>>("LogTarget to and from json works");
  check<JsonTest<MarkTarget>>("MarkTarget to and from json works");
  check<JsonTest<NFLogTarget>>("NFLogTarget to and from json works");
  check<JsonTest<NFQueueTarget>>("NFQueueTarget to and from json works");
  check<JsonTest<RateEstTarget>>("RateEstTarget to and from json works");
  check<JsonTest<SecMarkTarget>>("SecMarkTarget to and from json works");
  check<JsonTest<SynproxyTarget>>("SynproxyTarget to and from json works");
  check<JsonTest<TcpmssTarget>>("TcpmssTarget to and from json works");
  check<JsonTest<TcpOptStripTarget>>("TcpOptStripTarget to and from json works");
  check<JsonTest<TeeTarget>>("TeeTarget to and from json works");
  check<JsonTest<TproxyTarget>>("TproxyTarget to and from json works");
  check<JsonTest<RejectIPTarget>>("RejectIPTarget to and from json works");
  check<JsonTest<TtlTarget>>("TtlTarget to and from json works");
  check<JsonTest<HlTarget>>("HlTarget to and from json works");
  check<JsonTest<NptTarget>>("NptTarget to and from json works");
  check<JsonTest<RejectIP6Target>>("RejectIP6Target to and from json works");
}
