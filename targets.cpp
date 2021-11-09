#include <stdexcept>
#include <cstring>
#include "targets.hpp"

typedef std::runtime_error runtime_error;

DropTarget::DropTarget(){
  this->specs = -NF_DROP-1;
}

string DropTarget::getName() const{
  return "DROP";
}

json DropTarget::asJson() const{
  json j;
  j["verdict"] = this->specs;
  return j;
}

AcceptTarget::AcceptTarget(){
  this->specs = 0;
}

string AcceptTarget::getName() const{
  return "ACCEPT";
}

json AcceptTarget::asJson() const{
  json j;
  j["verdict"] = this->specs;
  return j;
}

ReturnTarget::ReturnTarget(){
  this->specs = 0;
}

string ReturnTarget::getName() const{
  return "RETURN";
}

json ReturnTarget::asJson() const{
  json j;
  j["verdict"] = this->specs;
  return j;
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

AuditTarget::AuditTarget(json j){
  this->specs.type = j["type"].get<unsigned char>();
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

json AuditTarget::asJson() const{
  json j;
  j["type"] = this->specs.type;
  return j;
}

ChecksumTarget::ChecksumTarget(){
  this->specs.operation = 0;
}

ChecksumTarget::ChecksumTarget(bool op){
  setOp(op);
}

ChecksumTarget::ChecksumTarget(json j){
  this->specs.operation = j["operation"].get<bool>();
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

json ChecksumTarget::asJson() const{
  json j;
  j["operation"] = (bool)this->specs.operation;
  return j;
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

ConnmarkTarget::ConnmarkTarget(json j){
  this->specs.ctmark = j["ctmark"].get<unsigned>();
  this->specs.ctmask = j["ctmask"].get<unsigned>();
  this->specs.nfmask = j["nfmask"].get<unsigned>();
  this->specs.mode = j["mode"].get<unsigned char>();
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

json ConnmarkTarget::asJson() const{
  json j;
  j["ctmark"] = this->specs.ctmark;
  j["ctmask"] = this->specs.ctmask;
  j["nfmask"] = this->specs.nfmask;
  j["mode"] = this->specs.mode;
  return j;
}

ConnsecmarkTarget::ConnsecmarkTarget(){
  this->specs.mode = 0;
}

ConnsecmarkTarget::ConnsecmarkTarget(unsigned char mode){
  setMode(mode);
}

ConnsecmarkTarget::ConnsecmarkTarget(json j){
  this->specs.mode = j["mode"];
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

json ConnsecmarkTarget::asJson() const{
  json j;
  j["mode"] = this->specs.mode;
  return j;
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

CTTarget::CTTarget(json j){
  this->specs.flags = j["flags"].get<unsigned short>();
  this->specs.zone = j["zone"].get<unsigned short>();
  this->specs.ct_events = j["ct_events"].get<unsigned>();
  this->specs.exp_events = j["exp_events"].get<unsigned>();
  strncpy(this->specs.helper, j["helper"].get<string>().c_str(), 16);
  strncpy(this->specs.timeout, j["timeout"].get<string>().c_str(), 32);
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

json CTTarget::asJson() const{
  json j;
  j["flags"] = this->specs.flags;
  j["zone"] = this->specs.zone;
  j["ct_events"] = this->specs.ct_events;
  j["exp_events"] = this->specs.exp_events;
  j["helper"] = string(this->specs.helper);
  j["timeout"] = string(this->specs.timeout);
  return j;
}


DscpTarget::DscpTarget(){
  this->specs.dscp = 0;
}

DscpTarget::DscpTarget(unsigned char value){
  setDscp(value);
}

DscpTarget::DscpTarget(json j){
  this->specs.dscp = j["dscp"].get<unsigned char>();
}

void DscpTarget::setDscp(unsigned char value){
  this->specs.dscp = value;
}

string DscpTarget::getName() const{
  return "DSCP";
}

json DscpTarget::asJson() const{
  json j;
  j["dscp"] = this->specs.dscp;
  return j;
}

TosTarget::TosTarget(){
  this->specs.tos_value = 0;
  this->specs.tos_mask = 0;
}

TosTarget::TosTarget(unsigned char value, unsigned char mask){
  setTos(value, mask);
}

TosTarget::TosTarget(json j){
  this->specs.tos_value = j["tos_value"].get<unsigned char>();
  this->specs.tos_mask = j["tos_mask"].get<unsigned char>();
}

void TosTarget::setTos(unsigned char value, unsigned char mask){
  this->specs.tos_value = value;
  this->specs.tos_mask = mask;
}

string TosTarget::getName() const{
  return "TOS";
}

json TosTarget::asJson() const{
  json j;
  j["tos_value"] = this->specs.tos_value;
  j["tos_mask"] = this->specs.tos_mask;
  return j;
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

HmarkTarget::HmarkTarget(json j){
  this->specs.flags = j["flags"].get<unsigned>();
  this->specs.proto_mask = j["proto_mask"].get<unsigned short>();
  this->specs.hashrnd = j["hashrnd"].get<unsigned>();
  this->specs.hmodulus = j["hmodulus"].get<unsigned>();
  this->specs.hoffset = j["hoffset"].get<unsigned>();
  this->specs.port_mask.v32 = j["port_mask"].get<unsigned>(); 
  this->specs.port_set.v32 = j["port_set"].get<unsigned>(); 
  for(int i = 0; i < 4; ++i){
    this->specs.src_mask.all[i] = j["src_mask"][i];
    this->specs.dst_mask.all[i] = j["dst_mask"][i];
  }
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

json HmarkTarget::asJson() const{
  json j;
  j["flags"] = this->specs.flags;
  j["proto_mask"] = this->specs.proto_mask;
  j["hashrnd"] = this->specs.hashrnd;
  j["hmodulus"] = this->specs.hmodulus;
  j["hoffset"] = this->specs.hoffset;
  j["port_mask"] = this->specs.port_mask.v32;
  j["port_set"] = this->specs.port_set.v32;
  for(int i = 0; i < 4; i++){
    j["src_mask"][i] = this->specs.src_mask.all[i];
    j["dst_mask"][i] = this->specs.dst_mask.all[i];
  }
  return j;
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

IdletimerTarget::IdletimerTarget(json j){
  this->specs.timeout = j["timeout"].get<unsigned>();
  strncpy(this->specs.label, j["label"].get<string>().c_str(), MAX_IDLETIMER_LABEL_SIZE);
}

void IdletimerTarget::setLabel(string label){
  strncpy(this->specs.label, label.c_str(), MAX_IDLETIMER_LABEL_SIZE);
}

void IdletimerTarget::setTimeout(unsigned int timeout){
  this->specs.timeout = timeout;
}

string IdletimerTarget::getName() const{
  return "IDLETIMER";
}

json IdletimerTarget::asJson() const{
  json j;
  j["timeout"] = this->specs.timeout;
  j["label"] = string(this->specs.label);
  return j;
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

LedTarget::LedTarget(json j){
  strncpy(this->specs.id, j["id"].get<string>().c_str(), 27);
  this->specs.always_blink = j["always_blink"].get<bool>();
  this->specs.delay = j["delay"].get<unsigned>();
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

json LedTarget::asJson() const{
  json j;
  j["id"] = string(this->specs.id);
  j["always_blink"] = (bool)this->specs.always_blink;
  j["delay"] = this->specs.delay;
  return j;
}

LogTarget::LogTarget(){
  memset(this->specs.prefix, 0, 30);
  setLevel(4);
  setFlags(0);
}

LogTarget::LogTarget(string prefix, unsigned char level, unsigned char flags){
  setPrefix(prefix);
  setLevel(level);
  setFlags(flags);
}

LogTarget::LogTarget(json j){
  this->specs.level = j["level"].get<unsigned char>();
  this->specs.logflags = j["logflags"].get<unsigned char>();
  strncpy(this->specs.prefix, j["prefix"].get<string>().c_str(), 30);
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

json LogTarget::asJson() const{
  json j;
  j["level"] = this->specs.level;
  j["logflags"] = this->specs.logflags;
  j["prefix"] = string(this->specs.prefix);
  return j;
}


MarkTarget::MarkTarget(){
  setMark(0);
  setMask(0);
}

MarkTarget::MarkTarget(unsigned int mark, unsigned int mask){
  setMark(mark);
  setMask(mask);
}

MarkTarget::MarkTarget(json j){
  this->specs.mark = j["mark"].get<unsigned>();
  this->specs.mask = j["mask"].get<unsigned>();
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

json MarkTarget::asJson() const{
  json j;
  j["mark"] = this->specs.mark;
  j["mask"] = this->specs.mask;
  return j;
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

NFLogTarget::NFLogTarget(json j){
  this->specs.len = j["len"].get<unsigned>();
  this->specs.group = j["group"].get<unsigned short>();
  this->specs.threshold = j["threshold"].get<unsigned short>();
  this->specs.flags = j["flags"].get<unsigned short>();
  this->specs.pad = j["pad"].get<unsigned short>();
  strncpy(this->specs.prefix, j["prefix"].get<string>().c_str(), 64);
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

json NFLogTarget::asJson() const{
  json j;
  j["len"] = this->specs.len;
  j["group"] = this->specs.group;
  j["threshold"] = this->specs.threshold;
  j["flags"] = this->specs.flags;
  j["pad"] = this->specs.pad;
  j["prefix"] = string(this->specs.prefix);
  return j;
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

NFQueueTarget::NFQueueTarget(json j){
  this->specs.queuenum = j["queuenum"].get<unsigned short>();
  this->specs.queues_total = j["queues_total"].get<unsigned short>();
  this->specs.flags = j["flags"].get<unsigned short>();
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

json NFQueueTarget::asJson() const{
  json j;
  j["queuenum"] = this->specs.queuenum;
  j["queues_total"] = this->specs.queues_total;
  j["flags"] = this->specs.flags;
  return j;
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

RateEstTarget::RateEstTarget(json j){
  strncpy(this->specs.name, j["name"].get<string>().c_str(), IFNAMSIZ);
  this->specs.interval = j["interval"].get<char>();
  this->specs.ewma_log = j["ewma_log"].get<unsigned char>();
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

json RateEstTarget::asJson() const{
  json j;
  j["name"] = string(this->specs.name);
  j["interval"] = this->specs.interval;
  j["ewma_log"] = this->specs.ewma_log;
  return j;
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

SecMarkTarget::SecMarkTarget(json j){
  this->specs.mode = j["mode"].get<unsigned char>();
  this->specs.secid = j["secid"].get<unsigned>();
  strncpy(this->specs.secctx, j["secctx"].get<string>().c_str(), SECMARK_SECCTX_MAX);
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

json SecMarkTarget::asJson() const{
  json j;
  j["mode"] = this->specs.mode;
  j["secid"] = this->specs.secid;
  j["secctx"] = string(this->specs.secctx);
  return j;
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

SynproxyTarget::SynproxyTarget(json j){
  this->specs.options = j["options"].get<unsigned char>();
  this->specs.wscale = j["wscale"].get<unsigned char>();
  this->specs.mss = j["mss"].get<unsigned short>();
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

json SynproxyTarget::asJson() const{
  json j;
  j["options"] = this->specs.options;
  j["wscale"] = this->specs.wscale;
  j["mss"] = this->specs.mss;
  return j;
}

TcpmssTarget::TcpmssTarget(){
  setMss(XT_TCPMSS_CLAMP_PMTU);
}

TcpmssTarget::TcpmssTarget(unsigned short mss){
  setMss(mss);
}

TcpmssTarget::TcpmssTarget(json j){
  this->specs.mss = j["mss"].get<unsigned short>();
}

void TcpmssTarget::setMss(unsigned short mss){
  this->specs.mss = mss;
}

string TcpmssTarget::getName() const{
  return "TCPMSS";
}

json TcpmssTarget::asJson() const{
  json j;
  j["mss"] = this->specs.mss;
  return j;
}

TcpOptStripTarget::TcpOptStripTarget(){
  memset(this->specs.strip_bmap, 0, 32);
}

TcpOptStripTarget::TcpOptStripTarget(unsigned int* options, int size){
  setOptions(options, size);
}

TcpOptStripTarget::TcpOptStripTarget(json j){
  for(int i = 0; i < 8; i++)
    this->specs.strip_bmap[i] = j["strip_bmap"][i];
}

void TcpOptStripTarget::setOptions(unsigned int* options, int size){
  for(int i = 0; i < size; i++)
    tcpoptstrip_set_bit(this->specs.strip_bmap, options[i]);
}

string TcpOptStripTarget::getName() const{
  return "TCPOPTSTRIP";
}

json TcpOptStripTarget::asJson() const{
  json j;
  for(int i = 0; i < 8; i++)
    j["strip_bmap"][i] = this->specs.strip_bmap[i];
  return j;
}

TeeTarget::TeeTarget(){
  memset(this->specs.gw.all, 0, 16);
  memset(this->specs.oif, 0, 16);
}

TeeTarget::TeeTarget(string ip){
  memset(this->specs.oif, 0, 16);
  setIp(ip);
}

TeeTarget::TeeTarget(json j){
  for(int i = 0; i < 4; i++)
    this->specs.gw.all[i] = j["gw"][i].get<unsigned>();
  for(int i = 0; i < 16; i++)
    this->specs.oif[i] = j["oif"][i].get<char>();
}

void TeeTarget::setIp(string ip){
  this->specs.gw = strToNfAddr(ip);
}

string TeeTarget::getName() const{
  return "TEE";
}

json TeeTarget::asJson() const{
  json j;
  for(int i = 0; i < 4; i++)
    j["gw"][i] = this->specs.gw.all[i];
  for(int i = 0; i < 16; i++)
    j["oif"][i] = this->specs.oif[i];
  return j;
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

TproxyTarget::TproxyTarget(json j){
  this->specs.mark_mask = j["mark_mask"].get<unsigned>();
  this->specs.mark_value = j["mark_value"].get<unsigned>();
  this->specs.lport = j["lport"].get<unsigned short>();
  for(int i = 0; i < 4; i++)
    this->specs.laddr.all[i] = j["laddr"][i];
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

json TproxyTarget::asJson() const{
  json j;
  j["mark_mask"] = this->specs.mark_mask;
  j["mark_value"] = this->specs.mark_value;
  j["lport"] = this->specs.lport;
  for(int i = 0; i < 4; i++)
    j["laddr"][i] = this->specs.laddr.all[i];
  return j;
}

RejectIPTarget::RejectIPTarget(){
  setType(IPT_ICMP_ECHOREPLY);
}

RejectIPTarget::RejectIPTarget(ipt_reject_with type){
  setType(type);
}

RejectIPTarget::RejectIPTarget(json j){
  this->specs.with = (ipt_reject_with)j["with"].get<int>();
}

void RejectIPTarget::setType(ipt_reject_with type){
  this->specs.with = type;
}

string RejectIPTarget::getName() const{
  return "REJECT";
}

json RejectIPTarget::asJson() const{
  json j;
  j["with"] = this->specs.with;
  return j;
}

TtlTarget::TtlTarget(){
  setEdit(0,0);
}

TtlTarget::TtlTarget(unsigned char value, unsigned char mode){
  setEdit(value, mode);
}

TtlTarget::TtlTarget(json j){
  this->specs.mode = j["mode"].get<unsigned char>();
  this->specs.ttl = j["ttl"].get<unsigned char>();
}

void TtlTarget::setEdit(unsigned char value, unsigned char mode){
  this->specs.mode = mode;
  this->specs.ttl = value;
}

string TtlTarget::getName() const{
  return "TTL";
}

json TtlTarget::asJson() const{
  json j;
  j["mode"] = this->specs.mode;
  j["ttl"] = this->specs.ttl;
  return j;
}

HlTarget::HlTarget(){
  setEdit(0, 0);
}

HlTarget::HlTarget(unsigned char value, unsigned char mode){
  setEdit(value, mode);
}

HlTarget::HlTarget(json j){
  this->specs.mode = j["mode"].get<unsigned char>();
  this->specs.hop_limit = j["hop_limit"].get<unsigned char>();
}


void HlTarget::setEdit(unsigned char value, unsigned char mode){
  this->specs.mode = mode;
  this->specs.hop_limit = value;
}

string HlTarget::getName() const{
  return "HL";
}

json HlTarget::asJson() const{
  json j;
  j["mode"] = this->specs.mode;
  j["hop_limit"] = this->specs.hop_limit;
  return j;
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

NptTarget::NptTarget(json j){
  for(int i = 0; i < 4; i++){
    this->specs.src_pfx.all[i] = j["src_pfx"][i].get<unsigned>();
    this->specs.dst_pfx.all[i] = j["dst_pfx"][i].get<unsigned>();
  }
  this->specs.src_pfx_len = j["src_pfx_len"].get<unsigned char>();
  this->specs.dst_pfx_len = j["dst_pfx_len"].get<unsigned char>();
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

json NptTarget::asJson() const{
  json j;
  for(int i = 0; i < 4; i++){
    j["src_pfx"][i] = this->specs.src_pfx.all[i];
    j["dst_pfx"][i] = this->specs.dst_pfx.all[i];
  }
  j["src_pfx_len"] = this->specs.src_pfx_len;
  j["dst_pfx_len"] = this->specs.dst_pfx_len;
  return j;
}

RejectIP6Target::RejectIP6Target(){
  setType(IP6T_ICMP6_ECHOREPLY);
}

RejectIP6Target::RejectIP6Target(ip6t_reject_with type){
  setType(type);
}

RejectIP6Target::RejectIP6Target(json j){
  this->specs.with = (ip6t_reject_with)j["with"].get<int>();
}

void RejectIP6Target::setType(ip6t_reject_with type){
  this->specs.with = type;
}

string RejectIP6Target::getName() const{
  return "REJECT";
}

json RejectIP6Target::asJson() const{
  json j;
  j["with"] = this->specs.with;
  return j;
}
