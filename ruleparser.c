#include "ruleparser.h"

void load_rules (char *path) {
     DIR *dir;
     char filepath[1024];

     if (strlen (path) < 1)
          die (1, "empty path names for loading rules\r\n");
     LIBXML_TEST_VERSION struct dirent *e;
     dir = opendir (path);

     if (dir == NULL)
          die (1, "Error opening rules directory %s\r\n", path);

     while ((e = readdir (dir))) {
          if (strncasecmp (&e->d_name[strlen (e->d_name) - 4], ".xml", 4) == 0) {
               xprintf (filepath, 1024, "%s/%s", path, e->d_name);
               debug (7, "Found rule file %s\r\n", filepath);
               parsexmlfile (filepath);
          }
     }
     xmlCleanupParser ();
     xmlMemoryDump ();

}

void parsexmlfile (char *path) {
     xmlTextReaderPtr reader;
     struct rules *rule;

     reader = xmlReaderForFile (path, NULL, XML_PARSE_DTDATTR | XML_PARSE_NOENT);

     if (reader == NULL)
          die (0, "Unable to parse rule file %s\r\n", path);
     else {
          // debug (6, "Processing rule file %s\r\n", path);
          while (xmlTextReaderRead (reader)) {
               rule = malloc_or_die ("Malloc error while loading rules\r\n", sizeof (struct rules));

               memset (rule, 0, sizeof (struct rules));

               if (load_xml_ruleset (reader, rule)) {
                    free_null (rule);

               } else {
                    list_add (&(rule->L), &(global.RL.L));
               }
          }
          if (xmlTextReaderIsValid (reader) != 1) {
               // debug (7, "Rule file %s does not validate\r\n", path);
          }
          xmlFreeTextReader (reader);

     }

}
void rule_purge () {
     struct rules *rule;
     struct list_head *lh, *tmp;

     list_for_each_safe (lh, tmp, &(global.RL.L)) {
          rule = list_entry (lh, struct rules, L);
          if (rule != NULL && !list_empty (&(global.RL.L))) {
               list_del (&(rule->L));
               free_null (rule);
          }

     }

}
int load_xml_ruleset (xmlTextReaderPtr reader, struct rules *rule) {    // this is ugly,messy,screw it! it works! bhahaha 
     const xmlChar *name, *value;
     char regex[4096], from[2048], to[2048];
     int err;
     memset (regex, 0, 4096);
     memset (from, 0, 2048);
     memset (to, 0, 2048);

     name = xmlTextReaderConstName (reader);
     if (name == NULL)
          name = BAD_CAST "--";

     value = xmlTextReaderConstValue (reader);
     if (strncmp ("ruleset", (const char *) name, 7) == 0) {
          while (xmlTextReaderMoveToNextAttribute (reader)) {
               value = xmlTextReaderConstValue (reader);
               name = xmlTextReaderConstName (reader);
               if (name == NULL)
                    name = BAD_CAST "--";

               if (strncasecmp ("name", (const char *) name, 4) == 0) {
                    if (strlen ((const char *) value) > 0) {
                         // debug (6, "\tRuleset - %s\r\n", value);
                         strncpy (rule->name, (const char *) value, 256);
                    }

               }

          }
          do {
               value = xmlTextReaderConstValue (reader);
               name = xmlTextReaderConstName (reader);
               if (name == NULL)
                    name = BAD_CAST "--";
               if (strncasecmp ("target", (const char *) name, 6) == 0) {
                    while (xmlTextReaderMoveToNextAttribute (reader)) {
                         value = xmlTextReaderConstValue (reader);
                         name = xmlTextReaderConstName (reader);
                         if (name == NULL)
                              name = BAD_CAST "--";
                         if (strncasecmp ("host", (const char *) name, 4) == 0) {
                              if (strlen ((const char *) value) > 0) {
                                   if (rule->target_count >= (MAX_REGEX - 1)) {
                                        //  debug (6, "Error found a rule with target count greater than configured maximum of %i\r\n", MAX_REGEX);
                                   } else {
                                        //    debug (6, "\t\tTarget -  %s\r\n", value);
                                        rule->targets[++rule->target_count] = make_target ((const char *) value);
                                   }
                              }
                         }
                    }
               } else if (strncasecmp ("rule", (const char *) name, 4) == 0) {
                    while (xmlTextReaderMoveToNextAttribute (reader)) {
                         value = xmlTextReaderConstValue (reader);
                         name = xmlTextReaderConstName (reader);
                         if (name == NULL)
                              name = BAD_CAST "--";
                         if (strncasecmp ("from", (const char *) name, 4) == 0) {
                              if (strlen ((const char *) value) > 0) {
                                   //      debug (6, "\t\tFrom - %s\r\n", value);
                                   strncpy (from, (const char *) value, 2048);
                              }
                         }
                         if (strncasecmp ("to", (const char *) name, 2) == 0) {
                              if (strlen ((const char *) value) > 0) {
                                   //       debug (6, "\t\tTo - %s\r\n", value);
                                   strncpy (to, (const char *) value, 2048);
                              }
                         }
                    }
                    if (strlen (to) < 1 || strlen (from) < 1)
                         return 1;      //found  a rule entry but no accompanying from/to attributes
                    else {
                         xprintf (regex, 4096, "s%c%s%c%s%cg", global.delimiter, from, global.delimiter, to,
                                  global.delimiter);
                         rule->job = pcrs_compile_command (regex, &err);
                         if (rule->job == NULL) {
                              die (0, "Error compiling pcrs regex %s\r\n", regex);
                              return 1;
                         }
                    }
               } else if (strncasecmp ("securecookie", (const char *) name, 12) == 0) { //dunno what to do with this but it's part of the xml
               }

          } while (xmlTextReaderNodeType (reader) != 15 && xmlTextReaderRead (reader)); //end element "ruleset"

     }
     if (rule->target_count > 0 && rule->job != NULL)
          return 0;

     return 1;
}

pcre *make_target (const char *target) {
     //yes in case you were wondering I copy pasted this from 
     //https://stackoverflow.com/questions/1421785/how-can-i-use-pcre-to-get-all-match-groups
     const char *error;
     char newtarget[20000];
     int erroffset;
     pcre *re;
     if (target[0] != '*') {
          re = pcre_compile (target,    /* the pattern */
                             PCRE_MULTILINE, &error,    /* for error message */
                             &erroffset,        /* for error offset */
                             0);        /* use default character tables */
     } else {
          xprintf (newtarget, 2083, ".%s", target);     //it really sucks that I have to do this but some people refuse to be pcre compatible :-/

          re = pcre_compile (newtarget, /* the pattern */
                             PCRE_MULTILINE, &error,    /* for error message */
                             &erroffset,        /* for error offset */
                             0);        /* use default character tables */

     }
     if (!re) {
          debug (6, "pcre_compile failed target:%s (offset: %d), %s\n", target, erroffset, error);
          return NULL;
     }

     return re;
}
