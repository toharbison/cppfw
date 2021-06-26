#include <stdexcept>
#include <cstring>
#include "targets.hpp"

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
  this->specs.src_mask.in.s_addr = inet_addr(mask.c_str());
  this->specs.flags |= XT_HMARK_FLAG(XT_HMARK_SADDR_MASK);
}

void HmarkTarget::setDst(string mask){
  this->specs.dst_mask.in.s_addr = inet_addr(mask.c_str());
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
