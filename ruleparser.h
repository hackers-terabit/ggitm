#ifndef RULEPARSER_H
#define RULEPARSER_H

#include <sys/types.h>
#include <dirent.h>
#include <libxml/xmlreader.h>

#include "util.h"
#include "pcrs/pcrs.h"
#include "list.h"

#define MAX_REGEX 2048          //20000 regex's per regex array, a bit high,had to bump it up from 2048 thanks to bit.ly

struct rules {
  pcrs_job *job;
  pcre *targets[MAX_REGEX];
  int target_count;
  char name[256];
  struct list_head L;
};

struct rules RL;                //rule list
static char delimiter = '`';    //why not,hope nobody uses ` in their url :P
void load_rules (char *path);
void parsexmlfile (char *path);
int load_xml_ruleset (xmlTextReaderPtr reader, struct rules *rule);
pcre *make_target (const char *target);
#endif
