#ifndef RULEPARSER_H
#define RULEPARSER_H

#include <sys/types.h>
#include <dirent.h>
#include <libxml/xmlreader.h>

#include "util.h"
#include "pcrs/pcrs.h"
#include "list.h"
#include "main.h"
#include "macros.h"


void load_rules (char *path);
void parsexmlfile (char *path);
int load_xml_ruleset (xmlTextReaderPtr reader, struct rules *rule);
pcre *make_target (const char *target);
void rule_purge();
#endif
