#include <stdexcept>
#include <cstring>
#include "targets.hpp"
#include "strToIp.hpp"

typedef std::runtime_error runtime_error;

template<class T>
T TemplateTarget<T>::getSpecs() const{
  return this->specs;
}

template<class T>
unsigned int TemplateTarget<T>::getSize() const{
  return sizeof(T);
}

AuditTarget::AuditTarget(){
  this->specs.type = 0;
}

AuditTarget::AuditTarget(unsigned char type){
  if(type <= XT_AUDIT_TYPE_MAX)
    this->specs.type = type;
  else
    throw runtime_error("Invalid audit type");
}

void AuditTarget::setType(unsigned char type){
  if(type <= XT_AUDIT_TYPE_MAX)
    this->specs.type = type;
  else
    throw runtime_error("Invalid audit type");
}

string AuditTarget::getName() const{
  return "AUDIT";
}

ChecksumTarget::ChecksumTarget(){
  this->specs.operation = 0;
}

ChecksumTarget::ChecksumTarget(bool op){
  setOp(op);
}

void ChecksumTarget::setOp(bool op){
  if(op)
    this->specs.operation = XT_CHECKSUM_OP_FILL;
  else
    this->specs.operation = 0;
}

string ChecksumTarget::getName() const{
  return "CHECKSUM";
}

ConnmarkTarget::ConnmarkTarget(){
  this->specs.ctmark = 0;
  this->specs.ctmask = 0;
  this->specs.nfmask = 0;
  this->specs.mode = 0;
}

ConnmarkTarget::ConnmarkTarget(unsigned char mode, unsigned int ctmark, unsigned int ctmask,
    unsigned int nfmask){
  this->specs.ctmark = ctmark;
  this->specs.ctmask = ctmask;
  this->specs.nfmask = nfmask;
  if(mode <= XT_CONNMARK_RESTORE)
    this->specs.mode = mode;
  else
    throw runtime_error("Invalid connmark target mode");
}

void ConnmarkTarget::setMark(unsigned int value, unsigned int mask){
  this->specs.ctmark = value;
  this->specs.ctmask = mask;
  this->specs.mode = XT_CONNMARK_SET;
}

void ConnmarkTarget::saveMark(unsigned int ctmask, unsigned int nfmask){
  this->specs.ctmask = ctmask;
  this->specs.nfmask = nfmask;
  this->specs.mode = XT_CONNMARK_SAVE;
}

void ConnmarkTarget::restoreMark(unsigned int ctmask, unsigned int nfmask){
  this->specs.ctmask = ctmask;
  this->specs.nfmask = nfmask;
  this->specs.mode = XT_CONNMARK_RESTORE;
}

string ConnmarkTarget::getName() const{
  return "CONNMARK";
}

ConnsecmarkTarget::ConnsecmarkTarget(){
  this->specs.mode = 0;
}

ConnsecmarkTarget::ConnsecmarkTarget(unsigned char mode){
  setMode(mode);
}

void ConnsecmarkTarget::setMode(unsigned char mode){
  if(mode == CONNSECMARK_SAVE || mode == CONNSECMARK_RESTORE)
    this->specs.mode = mode;
  else
    throw runtime_error("Invalid connsecmark target mode");
}

string ConnsecmarkTarget::getName() const{
  return "CONNSECMARK";
}

CTTarget::CTTarget(){
  this->specs.flags = 0;
  this->specs.zone = 0;
  this->specs.ct_events = 0;
  this->specs.exp_events = 0;
  memset(this->specs.helper, 0, 16);
  memset(this->specs.timeout, 0, 32);
}

CTTarget::CTTarget(bool noTrack, string helper, string timeout, unsigned int ctEvents, unsigned int expEvents,
    unsigned char flags, unsigned int zone){
  if(noTrack)
    this->specs.flags = XT_CT_NOTRACK; 
  else
    this->specs.flags = 0;
  setHelper(helper);
  setTimeout(timeout);
  setCTEvents(ctEvents);
  setExpEvents(expEvents);
  setZone(flags, zone);
}

void CTTarget::setNoTrack(){
  this->specs.flags |= XT_CT_NOTRACK;
}

void CTTarget::setHelper(string name){
  if(name.size() <= 16)
    strcpy(this->specs.helper, name.c_str());
  else
    throw runtime_error("CT helper name to large");
}

void CTTarget::setTimeout(string name){
  if(name.size() <= 32)
    strcpy(this->specs.timeout, name.c_str());
  else
    throw runtime_error("CT policy name to large");
}

void CTTarget::setCTEvents(unsigned int events){
  this->specs.ct_events = events;
}

void CTTarget::setExpEvents(unsigned int events){
  this->specs.exp_events = events;
}

void CTTarget::setZone(unsigned char flags, unsigned int id){
  if(flags <= XT_CT_MASK)
    this->specs.flags |= flags;
  else
    throw runtime_error("Invalid ct target flag(s)");
  if(id <= 0xffff)
    this->specs.zone = id;
  else
    throw runtime_error("Ct zone id to large");
}

string CTTarget::getName() const{
  return "CT";
}

DscpTarget::DscpTarget(){
  this->specs.dscp = 0;
}

DscpTarget::DscpTarget(unsigned char value){
  setDscp(value);
}

void DscpTarget::setDscp(unsigned char value){
  this->specs.dscp = value;
}

string DscpTarget::getName() const{
  return "DSCP";
}

TosTarget::TosTarget(){
  this->specs.tos_value = 0;
  this->specs.tos_mask = 0;
}

TosTarget::TosTarget(unsigned char value, unsigned char mask){
  setTos(value, mask);
}

void TosTarget::setTos(unsigned char value, unsigned char mask){
  this->specs.tos_value = value;
  this->specs.tos_mask = mask;
}

string TosTarget::getName() const{
  return "TOS";
}

HmarkTarget::HmarkTarget(){
  for(int i = 0; i < 4; ++i){
    this->specs.src_mask.all[i] = 0;
    this->specs.dst_mask.all[i] = 0;
  }
  this->specs.port_mask.v32 = 0;
  this->specs.port_set.v32 = 0;
  this->specs.flags = 0;
  this->specs.proto_mask = 0;
  this->specs.hashrnd = 0;
  this->specs.hmodulus = 0;
  this->specs.hoffset = 0;
}

void HmarkTarget::setSrc(string mask){
  this->specs.src_mask = strToNfAddr(mask);
  this->specs.flags |= XT_HMARK_FLAG(XT_HMARK_SADDR_MASK);
}

void HmarkTarget::setDst(string mask){
  this->specs.dst_mask = strToNfAddr(mask);
  this->specs.flags |= XT_HMARK_FLAG(XT_HMARK_DADDR_MASK);
}

void HmarkTarget::setSPort(unsigned int mask){
  if(mask <= 0xffff){
    this->specs.port_mask.p16.src = mask;
    this->specs.flags |= XT_HMARK_FLAG(XT_HMARK_SPORT_MASK);
  }
  else
    throw runtime_error("Hmark target source port mask to large");
}

void HmarkTarget::setDPort(unsigned int mask){
  if(mask <= 0xffff){
    this->specs.port_mask.p16.dst = mask;
    this->specs.flags |= XT_HMARK_FLAG(XT_HMARK_DPORT_MASK);
  }
  else
    throw runtime_error("Hmark target destination port mask to large");
}

void HmarkTarget::setProto(unsigned char mask){
  this->specs.proto_mask = mask;
  this->specs.flags |= XT_HMARK_FLAG(XT_HMARK_PROTO_MASK);
}

void HmarkTarget::setRnd(unsigned int value){
  this->specs.hashrnd = value;
  this->specs.flags |= XT_HMARK_FLAG(XT_HMARK_RND);
}

void HmarkTarget::setMod(unsigned int value){
  this->specs.hmodulus = value;
  this->specs.flags |= XT_HMARK_FLAG(XT_HMARK_MODULUS);
}

void HmarkTarget::setOffset(unsigned int value){
  this->specs.hoffset = value;
  this->specs.flags |= XT_HMARK_FLAG(XT_HMARK_OFFSET);
}

string HmarkTarget::getName() const{
  return "HMARK";
}

IdletimerTarget::IdletimerTarget(){
  memset(this->specs.label, 0, MAX_IDLETIMER_LABEL_SIZE);
  this->specs.timeout = 0;
}

IdletimerTarget::IdletimerTarget(string label, unsigned int timeout){
  if(label.size() <= MAX_IDLETIMER_LABEL_SIZE)
    setLabel(label);
  else
    throw runtime_error("Idle Timer label to large");
  setTimeout(timeout);
}

void IdletimerTarget::setLabel(string label){
  strcpy(this->specs.label, label.c_str());
}

void IdletimerTarget::setTimeout(unsigned int timeout){
  this->specs.timeout = timeout;
}

string IdletimerTarget::getName() const{
  return "IDLETIMER";
}

LedTarget::LedTarget(){
  memset(this->specs.id, 0, 27);
  setDelay(0);
  setAlwaysBlink(false);
}

LedTarget::LedTarget(string name, unsigned int delay, bool alwaysBlink){
  setName(name);
  setDelay(delay);
  setAlwaysBlink(alwaysBlink);
}

void LedTarget::setName(string name){
  strncpy(this->specs.id, name.c_str(), 26);
}

void LedTarget::setDelay(unsigned int delay){
  this->specs.delay = delay;
}

void LedTarget::setAlwaysBlink(bool alwaysBlink){
  this->specs.always_blink = (unsigned char) alwaysBlink;
}

string LedTarget::getName() const{
  return "LED";
}

LogTarget::LogTarget(){
  memset(this->specs.prefix, 0, 30);
  setLevel(0);
  setFlags(0);
}

LogTarget::LogTarget(string prefix, unsigned char level, unsigned char flags){
  setPrefix(prefix);
  setLevel(level);
  setFlags(flags);
}

void LogTarget::setPrefix(string prefix){
  strncpy(this->specs.prefix, prefix.c_str(), 30);
}

void LogTarget::setLevel(unsigned char level){
  this->specs.level = level;
}

void LogTarget::setFlags(unsigned char flags){
  if(flags <= XT_LOG_MASK)
    this->specs.logflags = flags;
  else
    throw runtime_error("Unrecognized log target flag");
}

string LogTarget::getName() const{
  return "LOG";
}

MarkTarget::MarkTarget(){
  setMark(0);
  setMask(0);
}

MarkTarget::MarkTarget(unsigned int mark, unsigned int mask){
  setMark(mark);
  setMask(mask);
}

void MarkTarget::setMark(unsigned int mark){
  this->specs.mark = mark;
}

void MarkTarget::setMask(unsigned int mask){
  this->specs.mask = mask;
}

string MarkTarget::getName() const{
  return "MARK";
}

NFLogTarget::NFLogTarget(){
  memset(this->specs.prefix, 0, 64);
  setGroup(XT_NFLOG_DEFAULT_GROUP);
  setThreshold(XT_NFLOG_DEFAULT_THRESHOLD);
  this->specs.flags = 0;
}

NFLogTarget::NFLogTarget(string prefix, unsigned int group, unsigned int threshold){
  setPrefix(prefix);
  setGroup(group);
  setThreshold(threshold);
  this->specs.flags = 0;
}

void NFLogTarget::setPrefix(string prefix){
  strncpy(this->specs.prefix, prefix.c_str(), 64);
}

void NFLogTarget::setGroup(unsigned int group){
  if(group <= 0xffff)
    this->specs.group = group;
  else
    throw runtime_error("Nf log group number too large");
}

void NFLogTarget::setThreshold(unsigned int threshold){
  if(threshold <= 0xffff)
    this->specs.threshold = threshold;
  else
    throw runtime_error("Nf log threshold number too large");
}
  
void NFLogTarget::setSize(unsigned int size){
  this->specs.len = size;
  this->specs.flags |= XT_NFLOG_F_COPY_LEN;
}

string NFLogTarget::getName() const{
  return "NFLOG";
}

NFQueueTarget::NFQueueTarget(){
  setBalance(0,0);
  this->specs.flags = 0;
}

NFQueueTarget::NFQueueTarget(unsigned int num){
  setNum(num);
  this->specs.flags = 0;
}

NFQueueTarget::NFQueueTarget(unsigned int first, unsigned int last){
  setBalance(first, last);
  this->specs.flags = 0;
}

void NFQueueTarget::setNum(unsigned int num){
  if(num <= 0xffff){
    this->specs.queuenum = num;
    this->specs.queues_total = 1;
  }
  else
    throw runtime_error("Nf queue number to large");
}

void NFQueueTarget::setBalance(unsigned int first, unsigned int last){
  if(last < first)
    throw runtime_error("Invalid nf queue interval");
  else if(first <= 0xffff && last <= 0xffff){
    this->specs.queuenum = first;
    this->specs.queues_total = last - first + 1;
  }
  else
    throw runtime_error("Nf queue number to large");
}

void NFQueueTarget::setBypass(){
  this->specs.flags |= NFQ_FLAG_BYPASS;
}

void NFQueueTarget::setCpuFanout(){
  this->specs.flags |= NFQ_FLAG_CPU_FANOUT;
}

string NFQueueTarget::getName() const{
  return "NFQUEUE";
}

RateEstTarget::RateEstTarget(){
  memset(this->specs.name, 0, IFNAMSIZ);
  setInterval(0);
  setEwmaLog(0);
}

RateEstTarget::RateEstTarget(string name, char interval, unsigned char ewmalog){
  setName(name);
  setInterval(interval);
  setEwmaLog(ewmalog);
}

void RateEstTarget::setName(string name){
  strncpy(this->specs.name, name.c_str(), IFNAMSIZ);
}

void RateEstTarget::setInterval(char interval){
  this->specs.interval = interval;
}

void RateEstTarget::setEwmaLog(unsigned char ewmalog){
  this->specs.ewma_log = ewmalog;
}

string RateEstTarget::getName() const{
  return "RATEEST";
}

SecMarkTarget::SecMarkTarget(){
  this->specs.mode = SECMARK_MODE_SEL;
  setSecID(0);
  memset(this->specs.secctx, 0, SECMARK_SECCTX_MAX);
}

SecMarkTarget::SecMarkTarget(unsigned int secid, string context){
  this->specs.mode = SECMARK_MODE_SEL;
  setSecID(secid);
  setContext(context);
}

void SecMarkTarget::setSecID(unsigned int secid){
  this->specs.secid = secid;
}

void SecMarkTarget::setContext(string context){
  strncpy(this->specs.secctx, context.c_str(), SECMARK_SECCTX_MAX);
}

string SecMarkTarget::getName() const{
  return "SECMARK";
}

SynproxyTarget::SynproxyTarget(){
  this->specs.options = 0;
  this->specs.wscale = 0;
  this->specs.mss = 0;
}

SynproxyTarget::SynproxyTarget(unsigned short mss, unsigned char wscale){
  this->specs.options = 0;
  setMss(mss);
  setWinScale(wscale);
}

void SynproxyTarget::setMss(unsigned short mss){
  this->specs.mss = mss;
  this->specs.options |= XT_SYNPROXY_OPT_MSS;
}

void SynproxyTarget::setWinScale(unsigned char wscale){
  this->specs.wscale = wscale;
  this->specs.options |= XT_SYNPROXY_OPT_WSCALE;
}

void SynproxyTarget::setSackPerm(){
  this->specs.options |= XT_SYNPROXY_OPT_SACK_PERM;
}

void SynproxyTarget::setTimestamps(){
  this->specs.options |= XT_SYNPROXY_OPT_TIMESTAMP;
}

string SynproxyTarget::getName() const{
  return "SYNPROXY";
}

TcpmssTarget::TcpmssTarget(){
  setMss(XT_TCPMSS_CLAMP_PMTU);
}

TcpmssTarget::TcpmssTarget(unsigned short mss){
  setMss(mss);
}

void TcpmssTarget::setMss(unsigned short mss){
  this->specs.mss = mss;
}

string TcpmssTarget::getName() const{
  return "TCPMSS";
}

TcpOptStripTarget::TcpOptStripTarget(){
  memset(this->specs.strip_bmap, 0, 32);
}

TcpOptStripTarget::TcpOptStripTarget(unsigned int* options, int size){
  setOptions(options, size);
}

void TcpOptStripTarget::setOptions(unsigned int* options, int size){
  for(int i = 0; i < size; i++)
    tcpoptstrip_set_bit(this->specs.strip_bmap, options[i]);
}

string TcpOptStripTarget::getName() const{
  return "TCPOPTSTRIP";
}

TeeTarget::TeeTarget(){
  memset(this->specs.gw.all, 0, 16);
  memset(this->specs.oif, 0, 16);
}

TeeTarget::TeeTarget(string ip){
  memset(this->specs.oif, 0, 16);
  setIp(ip);
}

void TeeTarget::setIp(string ip){
  this->specs.gw = strToNfAddr(ip);
}

string TeeTarget::getName() const{
  return "TEE";
}

TproxyTarget::TproxyTarget(){
  setMark(0,0);
  memset(this->specs.laddr.all, 0, 16);
  this->specs.lport = 0;
}

TproxyTarget::TproxyTarget(unsigned short port){
  setMark(0,0);
  memset(this->specs.laddr.all, 0, 16);
  setPort(port);
}

TproxyTarget::TproxyTarget(unsigned short port, string ip){
  setMark(0,0);
  setIp(ip);
  setPort(port);
}

void TproxyTarget::setPort(unsigned short port){
  unsigned short be = port << 8;
  be |= port >> 8;
  this->specs.lport = be;
}

void TproxyTarget::setIp(string ip){
  this->specs.laddr = strToNfAddr(ip);
}

void TproxyTarget::setMark(unsigned int mark, unsigned int mask){
  this->specs.mark_value = mark;
  this->specs.mark_mask = mask;
}

string TproxyTarget::getName() const{
  return "TPROXY";
}

RejectIPTarget::RejectIPTarget(){
  setType(IPT_ICMP_ECHOREPLY);
}

RejectIPTarget::RejectIPTarget(ipt_reject_with type){
  setType(type);
}

void RejectIPTarget::setType(ipt_reject_with type){
  this->specs.with = type;
}

string RejectIPTarget::getName() const{
  return "REJECT";
}

TtlTarget::TtlTarget(){
  setEdit(0,0);
}

TtlTarget::TtlTarget(unsigned char value, unsigned char mode){
  setEdit(value, mode);
}

void TtlTarget::setEdit(unsigned char value, unsigned char mode){
  this->specs.mode = mode;
  this->specs.ttl = value;
}

string TtlTarget::getName() const{
  return "TTL";
}

HlTarget::HlTarget(){
  setEdit(0, 0);
}

HlTarget::HlTarget(unsigned char value, unsigned char mode){
  setEdit(value, mode);
}

void HlTarget::setEdit(unsigned char value, unsigned char mode){
  this->specs.mode = mode;
  this->specs.hop_limit = value;
}

string HlTarget::getName() const{
  return "HL";
}

NptTarget::NptTarget(){
  memset(this->specs.src_pfx.all, 0, 16);
  memset(this->specs.dst_pfx.all, 0, 16);
  this->specs.src_pfx_len = 0;
  this->specs.dst_pfx_len = 0;
}

NptTarget::NptTarget(string src, string dst, unsigned char srcLen, unsigned char dstLen){
  setTranslate(src, dst, srcLen, dstLen);
}

void NptTarget::setTranslate(string src, string dst, unsigned char srcLen, unsigned char dstLen){
  this->specs.src_pfx = strToNfAddr(src);
  this->specs.dst_pfx = strToNfAddr(dst);
  this->specs.src_pfx_len = srcLen;
  this->specs.dst_pfx_len = dstLen;
}

string NptTarget::getName() const{
  return "NPT";
}

RejectIP6Target::RejectIP6Target(){
  setType(IP6T_ICMP6_ECHOREPLY);
}

RejectIP6Target::RejectIP6Target(ip6t_reject_with type){
  setType(type);
}

void RejectIP6Target::setType(ip6t_reject_with type){
  this->specs.with = type;
}

string RejectIP6Target::getName() const{
  return "REJECT";
}
