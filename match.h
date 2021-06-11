#ifndef MATCH_H
#define MATCH_H

#include <string>
#include <cstdint>
#include "match_headers.h"
#define string std::string

class Match{
  public:
  /* Constructor */
  Match(){};

  /* Returns name of match */
  string getName() = 0;
};

class AddrtypeMatch : Match{
  public:
  /* Constructors */
  AddrtypeMatch();
  AddrtypeMatch(string src, string dst);

  /* Sets address type of source ip */
  void setSrc(string src);
  /* Sets address type of destination ip */
  void setDst(string dst);

  /* Limits matching to incoming interface */
  void limitIFace();
  /* Limits matching to outgoing interface */
  void limitOFace();

  /* Returns match specifictions */
  xt_addrtype_info_v1 getSpecs();

  private:
  xt_addrtype_info_v1 specs;
  uint16_t strToType(string str);
};

class BpfMatch : Match{
  public:
  /* Constructors */
  BpfMatch();
  BpfMatch(string progPath);
  BpfMatch(char* code);

  /* Sets program path of BPF object */
  void setPath(string progPath);
  /* Sets path of pinned BPF program */
  void setPinPath(string progPath);
  /* Sets byte code of a BPF program */
  void setProg(unsigned char* code);

  /* Returns match specifications */
  xt_bpf_info_v1 getSpecs();

  private:
  xt_bpf_info_v1 specs;
};

class CgroupMatch : Match{
  public:
  /* Constructors */
  CgroupMatch();
  CgroupMatch(string path);
  CgroupMatch(uint32_t classid);

  /* Sets path of cgroup2 membership */
  void setPath(string path);
  /* Sets cgroup net_cls classid */
  void setClassId(uint32_t classid);

  /* Returns match specifications */
  xt_cgroup_info_v2 getSpecs();

  private:
  xt_cgroup_info_v2 specs;
};

class ClusterMatch : Match{
  public:
  /* Constuctors */
  ClusterMatch();
  ClusterMatch(uint32_t total, uint32_t nodeMask, uint32_t hashSeed);

  /* Sets total number of nodes */
  void setNumNodes(uint32_t total);
  /* Sets local node mask */
  void setNodeMask(uint32_t nodeMask);
  /* Sets seed of Jenkins hash */
  void setSeed(uint32_t hashSeed);
  
  /* Inverts node mask */
  void invertMask();

  /* Returns match specifications */
  xt_cluster_match_info getSpecs();

  private:
  xt_cluster_match_info specs;
};

class CommentMatch : Match{
    public:
    /* Constructor */
    CommentMatch();
    CommentMatch(string comment);

    /* Sets comment */
    void setComment(string comment);

    /* Returns metch specifications */
    xt_comment_info getSpecs();

    private:
    xt_comment_info specs;
};

class ConnbytesMatch : Match


#endif
