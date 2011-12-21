/*
 * NAXSI, a web application firewall for NGINX
 * Copyright (C) 2011, Thibault 'bui' Koechlin
 *  
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "naxsi.h"


char	*
strnchr(const char *s, int c, int len)
{
  int	cpt;
  for (cpt = 0; cpt < len && s[cpt]; cpt++)
    if (s[cpt] == c) 
      return ((char *) s+cpt);
  return (NULL);
}

char	*
strncasechr(const char *s, int c, int len)
{
  int	cpt;
  for (cpt = 0; cpt < len && s[cpt]; cpt++)
    if (tolower(s[cpt]) == c) 
      return ((char *) s+cpt);
  return (NULL);
}

/*
** strstr: faster, stronger, harder
** (because strstr from libc is very slow)
*/
char *
strfaststr(unsigned char *haystack, unsigned int hl, 
		 unsigned char *needle, unsigned int nl)
{
  char	*cpt, *found, *end;
  if (hl < nl || !haystack || !needle || !nl || !hl) return (NULL);
  cpt = (char *) haystack;
  end = (char *) haystack + hl;
  while (cpt < end) {
      found = strncasechr((const char *) cpt, (int) needle[0], hl);
      if (!found) return (NULL);
      if (nl == 1) return (found);
      if (!strncasecmp((const char *)found+1, (const char *) needle+1, nl-1))
	return ((char *) found);
      else {
	  if (found+nl >= end)
	    break;
	  if (found+nl < end)
	    cpt = found+1;
	}
    }
  return (NULL);
}

/*
** This function will take the whitelist basicrules generated during the configuration
** parsing phase, and aggregate them to build hashtables according to the matchzones.
** 
** As whitelist can be in the form :
** "mz:$URL:bla|$ARGS_VAR:foo"
** "mz:$URL:bla|ARGS"
** "mz:$HEADERS_VAR:Cookie"
** ...
**
** So, we will aggregate all the rules that are pointing to the same URL together, 
** as well as rules targetting the same argument name / zone.
** 
** I do agree that this is not convenient to read, but splitting this function is not convenient
** as this is basically a big for() going through the list. Yes, not an excuse, laziness :p
*/
//#define whitelist_heavy_debug
//#define whitelist_debug
#ifdef OLD_BROKEN_HASHTABLES
ngx_int_t  
ngx_http_dummy_create_hashtables(ngx_http_dummy_loc_conf_t *dlc, 
				 ngx_conf_t *cf)
{
  unsigned int	i,z, x;
  ngx_http_rule_t	*rl, **dr;
  ngx_http_basic_rule_t	*br;
  ngx_http_custom_rule_location_t *loc;
  ngx_hash_init_t     hash_init;
  ngx_array_t		*elements_uri, *elements_body, 
    *elements_vars, *elements_headers;
  ngx_hash_key_t*     arr_node;
  ngx_array_t         *my_wlr;
  int		found, count;
  ngx_http_whitelist_rule_t *wlr;
  ngx_http_whitelist_location_t	*wl_loc;
  ngx_int_t	*tmp_ptr;
  int	var_idx = -1;
  enum DUMMY_MATCH_ZONE zone = UNKNOWN;
  
  /* Construct hashtable of WhiteList here */
  if (!dlc)
    return (NGX_ERROR);
  if (!dlc->whitelist_rules)
    return (NGX_OK);
  /* Go through each whitelist_rules, which are in fact http_rules. We'll transform them into REAL whitelist */
  /* Allocate the array where we are going to store "assembled" rules */
  my_wlr = ngx_array_create(cf->pool, dlc->whitelist_rules->nelts, 
			    sizeof(ngx_http_whitelist_rule_t));
  if (!my_wlr)
    return (NGX_ERROR);
  for(i = 0; i < dlc->whitelist_rules->nelts; i++) {
    var_idx = -1;
    rl = dlc->whitelist_rules->elts;
    br = rl[i].br;
#ifdef whitelist_heavy_debug
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
		       "rule %d is whitelisted somehow", rl[i].wl_id[0]);
#endif

    /* 
    ** No custom location in whitelist, means the rule is disabled.
    ** Push it into disabled rules, and it will always match in "is_rule_whitelisted" func.
    */
    if (!br->custom_locations) {
#ifdef whitelist_heavy_debug
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			 "Disabled rule [%d]", rl[i].wl_id[0]);
#endif
      if (!dlc->disabled_rules)
	dlc->disabled_rules = ngx_array_create(cf->pool, 4, 
					       sizeof(ngx_http_rule_t *));
      if (!dlc->disabled_rules)
	return (NGX_ERROR);
      dr = ngx_array_push(dlc->disabled_rules);
      if (!dr)
	return (NGX_ERROR);
      *dr = &(rl[i]);
      continue;
    }
    /*
    ** Else, the rule targets a specific URL and/or argument.
    ** Here, we identify what the rule is targetting :
    ** URL
    ** ARGS_VAR
    ** ...
    */
    loc = br->custom_locations->elts;
    for (z = 0; z < br->custom_locations->nelts; z++) {
      if (loc[z].specific_url) {
#ifdef whitelist_heavy_debug
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			   "whitelist has URI %V", &(loc[z].target));
#endif
	var_idx = z;
	zone = URL;
	break;
      }
      if (loc[z].body_var) {
#ifdef whitelist_heavy_debug
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			   "whitelist has body_var %V", &(loc[z].target));
#endif
	var_idx = z;
	zone = BODY;
      }
      if (loc[z].headers_var) {
#ifdef whitelist_heavy_debug
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			   "whitelist has header_var %V", &(loc[z].target));
#endif
	var_idx = z;
	zone = HEADERS;
      }
      if (loc[z].args_var) {
#ifdef whitelist_heavy_debug
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			   "whitelist has arg_var %V", &(loc[z].target));
#endif
	var_idx = z;
	zone = ARGS;
      }
    }
    /*
    ** Try to locate other existing whiterules on this name/zone
    */
    wlr = my_wlr->elts;
    found = 0;
    for(x = 0; x < my_wlr->nelts; x++) {
      if (wlr[x].zone == zone && 
	  !strcmp((const char *)wlr[x].name->data, 
		  (const char *)loc[var_idx].target.data)) {
#ifdef whitelist_heavy_debug
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			   "Found whitelist with name %V and zone %d", 
			   &(loc[var_idx].target), zone);
#endif
	wlr = &(wlr[x]);
	found = 1;
	break;
      }
    }
    /*
    ** if we didn't found it, create one, and copy name+zone
    */
    if (!found) {
#ifdef whitelist_heavy_debug
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			 "Created whitelist name %V zone %s", 
			 &(loc[var_idx].target),
			 zone == ARGS ? "ARGS" : zone == HEADERS ? 
			 "HEADERS" : zone == URL ? "URI" : zone == BODY 
			 ? "BODY" : "UNKNOWN");
#endif
      wlr = ngx_array_push(my_wlr);
      if (!wlr)
	return (NGX_ERROR);
      memset(wlr, 0, sizeof(ngx_http_whitelist_rule_t));
      wlr->name = &(loc[var_idx].target);
      wlr->zone = zone;
    }
    /*
    ** now we point, either to new structure, either to an existing one. only the name+zone is filled,
    */
    if (!wlr->whitelist_locations)
      wlr->whitelist_locations = ngx_array_create(cf->pool, 4, sizeof(ngx_http_whitelist_location_t));
#ifdef whitelist_heavy_debug
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "pushing new location to whitelist.");
#endif
    wl_loc = ngx_array_push(wlr->whitelist_locations);
    if (!wl_loc)
      return (NGX_ERROR);
    memset(wl_loc, 0, sizeof(ngx_http_whitelist_location_t));
    /*
    ** Add the IDs of the rule to the existing/new one
    */
    if (!wl_loc->ids) {
      wl_loc->ids = ngx_array_create(cf->pool, 3, sizeof(ngx_int_t));
      if (!wl_loc->ids)
	return (NGX_ERROR);
    }
    for (count = 0; rl[i].wl_id[count] >= 0; count++) {
      tmp_ptr = ngx_array_push(wl_loc->ids);
      if (!tmp_ptr)
	return (NGX_ERROR);
      *tmp_ptr = rl[i].wl_id[count];
    }//ZZZ
    /*
    ** If the WL is targetting a specific URL (mz:$URL:/bar|$ARGS_VAR:foo) , we need to push the sub-locations,
    ** we handle as well mz:$URL:/bar|ARGS
    */
    for (z = 0; z < br->custom_locations->nelts; z++) {
      /*
      ** In case it's a non specific location (mz:$URL:/bar|ARGS)
      ** then, we will only have "one" custom location, has flag/body/headers/url/args
      ** flag will be set in the basic_rule and not in the custom_location.
      ** then, push this anyway.
      */
      if (!(br->body || br->headers || br->url || br->args) && 
	  loc[z].specific_url) {
#ifdef whitelist_heavy_debug
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "discarding rule push !");
#endif
	continue;
      }
#ifdef whitelist_heavy_debug
      if (br->body || br->headers || br->url || br->args)
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			   "Pushing to LOCATIONS [GENERIC ZONE]", 
			   &(loc[z].target));
      else
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			   "Pushing to LOCATIONS %V", &(loc[z].target));
#endif
      wl_loc = ngx_array_push(wlr->whitelist_locations);
      if (!wl_loc)
	return (NGX_ERROR);
      memset(wl_loc, 0, sizeof(ngx_http_whitelist_location_t));
      if (br->body)
	wl_loc->body = 1;
      if (br->url)
	wl_loc->url = 1;
      if (br->headers)
	wl_loc->headers = 1;
      if (br->args)
	wl_loc->args = 1;
      //add
      if (loc[z].specific_url) {
	wl_loc->url = 1;
      }
      //add
      if (loc[z].args_var)
	wl_loc->args_var = 1;
      if (loc[z].body_var)
	wl_loc->body_var = 1;
      if (loc[z].headers_var)
	wl_loc->headers_var = 1;
      if (loc[z].target.len > 0)
	wl_loc->name = &(loc[z].target);
      else
	wl_loc->name = NULL;
      /* if we already have some ids, it means that multiple whitelist rules
	 are targetting same url & argument. If so, we need to alloc a new array to store both. */
      if (!wl_loc->ids) {
	wl_loc->ids = ngx_array_create(cf->pool, 1, sizeof(ngx_int_t));
	if (!wl_loc->ids)
	  return (NGX_ERROR);
      }
      for (count = 0; rl[i].wl_id[count] >= 0; count++) {
	tmp_ptr = ngx_array_push(wl_loc->ids);
	if (!tmp_ptr)
	  return (NGX_ERROR);
	*tmp_ptr = rl[i].wl_id[count];
      }
#ifdef whitelist_debug
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			 "[WHITELIST] args:%d|args_var:%d|headers:%d|headers_var:%d|body:%d|body_var:%d|URL:%d|spec_URL:%d",
			 br->args, br->args_var, br->headers, 
			 br->headers_var, br->body, br->body_var,
			 br->url, loc[z].specific_url);
#endif
    }
  }
  /*
  ** Go once again over the list of freshly assembled white list, and create 
  ** hash table.
  */
  wlr = my_wlr->elts;
  int	my_hash_init_size = my_wlr->nelts/4 == 0 ? 1 : my_wlr->nelts/4;
  elements_uri = ngx_array_create(cf->pool, my_hash_init_size, 
				  sizeof(ngx_hash_key_t));
  elements_headers = ngx_array_create(cf->pool, my_hash_init_size, 
				      sizeof(ngx_hash_key_t));
  elements_vars = ngx_array_create(cf->pool, my_hash_init_size, 
				   sizeof(ngx_hash_key_t));
  elements_body = ngx_array_create(cf->pool, my_hash_init_size, 
				   sizeof(ngx_hash_key_t));
  for(i = 0; i < my_wlr->nelts; i++) {
#ifdef whitelist_debug
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "pushing for zone %s with name %V",
		       wlr[i].zone == BODY ? "BODY" : wlr[i].zone == HEADERS 
		       ? "HEADERS" : wlr[i].zone == ARGS ? "ARGS" :
		       wlr[i].zone == URL ? "URL" : "UNKNOWN", wlr[i].name);
#endif
      switch (wlr[i].zone) {
	case BODY:
	  arr_node = (ngx_hash_key_t*) ngx_array_push(elements_body);
	  break;
	case HEADERS:
	  arr_node = (ngx_hash_key_t*) ngx_array_push(elements_headers);
	  break;
	case ARGS:
	  arr_node = (ngx_hash_key_t*) ngx_array_push(elements_vars);
	  break;
	case URL:
	  arr_node = (ngx_hash_key_t*) ngx_array_push(elements_uri);
	  break;
	default:
	  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "unknown zone ..");
	  return (NGX_ERROR);
	  break;
	}
      /*
      ** no need to memset arr_node here, as all fields are manually filled.
      */
      if (!arr_node)
	return (NGX_ERROR);
      arr_node->key       = *(wlr[i].name);
      arr_node->key_hash  = ngx_hash_key_lc(wlr[i].name->data, 
					    wlr[i].name->len);
      arr_node->value     = (void*) &(wlr[i]);
    }
  if (elements_uri->nelts > 0) {
      dlc->wlr_url_hash = (ngx_hash_t*) ngx_pcalloc(cf->pool, 
						    sizeof(ngx_hash_t));
      hash_init.hash      = dlc->wlr_url_hash;
      hash_init.key       = &ngx_hash_key_lc;
      hash_init.max_size  = 1024;
      hash_init.bucket_size = 512;
      hash_init.name      = "wlr_url_hash";
      hash_init.pool           = cf->pool;
      hash_init.temp_pool      = NULL;
      if (ngx_hash_init(&hash_init, (ngx_hash_key_t*) elements_uri->elts, 
			elements_uri->nelts) != NGX_OK) {
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "$URI hashtable init failed");
	return (NGX_ERROR);
      }
#ifdef whitelist_debug
      else
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			   "$URI hashtable init OK, %d items", 
			   dlc->wlr_url_hash->size);
#endif
  }
  if (elements_body->nelts > 0) {
    dlc->wlr_body_hash = (ngx_hash_t*) ngx_pcalloc(cf->pool, 
						   sizeof(ngx_hash_t));
    hash_init.hash      = dlc->wlr_body_hash;
      hash_init.key       = &ngx_hash_key_lc;
      hash_init.max_size  = 1024*10;
      hash_init.bucket_size = 256;
      hash_init.name      = "wlr_body_hash";
      hash_init.pool           = cf->pool;
      hash_init.temp_pool      = NULL;
      if (ngx_hash_init(&hash_init, (ngx_hash_key_t*) elements_body->elts, 
			elements_body->nelts) != NGX_OK) {
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "$BODY hashtable init failed");
	return (NGX_ERROR);
      }
#ifdef whitelist_debug
      else
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "$BODY hashtable init OK, %d items", dlc->wlr_body_hash->size);
#endif
  }
  if (elements_vars->nelts > 0) {
    dlc->wlr_args_hash = (ngx_hash_t*) ngx_pcalloc(cf->pool, 
						   sizeof(ngx_hash_t));
      hash_init.hash      = dlc->wlr_args_hash;
      hash_init.key       = &ngx_hash_key_lc;
      hash_init.max_size  = 1024*10;
      hash_init.bucket_size = 256;
      hash_init.name      = "wlr_vars_hash";
      hash_init.pool           = cf->pool;
      hash_init.temp_pool      = NULL;
      if (ngx_hash_init(&hash_init, (ngx_hash_key_t*) elements_vars->elts, 
			elements_vars->nelts) != NGX_OK) {
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "$ARGS hashtable init failed");
	return (NGX_ERROR);
      }
#ifdef whitelist_debug
      else
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			   "$ARGS hashtable init OK, %d items final, %d items in list", 
			   dlc->wlr_args_hash->size, elements_vars->nelts);
#endif
  }
  if (elements_headers->nelts > 0) {
      dlc->wlr_headers_hash = (ngx_hash_t*) ngx_pcalloc(cf->pool, 
							sizeof(ngx_hash_t));
      hash_init.hash      = dlc->wlr_headers_hash;
      hash_init.key       = &ngx_hash_key_lc;
      hash_init.max_size  = 1024*10;
      hash_init.bucket_size = 256;
      hash_init.name      = "wlr_headers_hash";
      hash_init.pool           = cf->pool;
      hash_init.temp_pool      = NULL;
      if (ngx_hash_init(&hash_init, (ngx_hash_key_t*) elements_headers->elts, 
			elements_headers->nelts) != NGX_OK) {
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "$HEADERS hashtable init failed");
	return (NGX_ERROR);
      }
#ifdef whitelist_debug
      else
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "$HEADERS hashtable init OK, %d items", dlc->wlr_headers_hash->size);
#endif
      
  }

  return (NGX_OK);
}
#endif

/*
** Patched ngx_unescape_uri : 
** The original one does not care if the character following % is in valid range.
** For example, with the original one :
** '%uff' -> 'uff'
*/
void
naxsi_unescape_uri(u_char **dst, u_char **src, size_t size, ngx_uint_t type)
{
    u_char  *d, *s, ch, c, decoded;
    enum {
        sw_usual = 0,
        sw_quoted,
        sw_quoted_second
    } state;

    d = *dst;
    s = *src;

    state = 0;
    decoded = 0;

    while (size--) {

        ch = *s++;

        switch (state) {
        case sw_usual:
            if (ch == '?'
                && (type & (NGX_UNESCAPE_URI|NGX_UNESCAPE_REDIRECT)))
            {
                *d++ = ch;
                goto done;
            }

            if (ch == '%') {
                state = sw_quoted;
                break;
            }

            *d++ = ch;
            break;

        case sw_quoted:

            if (ch >= '0' && ch <= '9') {
                decoded = (u_char) (ch - '0');
                state = sw_quoted_second;
                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                decoded = (u_char) (c - 'a' + 10);
                state = sw_quoted_second;
                break;
            }

            /* the invalid quoted character */

            state = sw_usual;
	    *d++ = '%';
            *d++ = ch;

            break;

        case sw_quoted_second:

            state = sw_usual;

            if (ch >= '0' && ch <= '9') {
                ch = (u_char) ((decoded << 4) + ch - '0');

                if (type & NGX_UNESCAPE_REDIRECT) {
                    if (ch > '%' && ch < 0x7f) {
                        *d++ = ch;
                        break;
                    }

                    *d++ = '%'; *d++ = *(s - 2); *d++ = *(s - 1);

                    break;
                }

                *d++ = ch;

                break;
            }

            c = (u_char) (ch | 0x20);
            if (c >= 'a' && c <= 'f') {
                ch = (u_char) ((decoded << 4) + c - 'a' + 10);

                if (type & NGX_UNESCAPE_URI) {
                    if (ch == '?') {
                        *d++ = ch;
                        goto done;
                    }

                    *d++ = ch;
                    break;
                }

                if (type & NGX_UNESCAPE_REDIRECT) {
                    if (ch == '?') {
                        *d++ = ch;
                        goto done;
                    }

                    if (ch > '%' && ch < 0x7f) {
                        *d++ = ch;
                        break;
                    }

                    *d++ = '%'; *d++ = *(s - 2); *d++ = *(s - 1);
                    break;
                }

                *d++ = ch;

                break;
            }

            /* the invalid quoted character */

            break;
        }
    }

done:

    *dst = d;
    *src = s;
}






/*
  next gen hashtables
*/
/*
  how lazy ? so lazy :)
 */


#define whitelist_light_debug
//#define whitelist_heavy_debug
#define whitelist_debug

/* #ifdef whitelist_heavy_debug */
/* #define whitelist_light_debug */
/* #define whitelist_debug */
/* #endif */

/* #ifdef whitelist_debug */
/* #define whitelist_light_debug */
/* #endif */


/* push rule into disabled rules. */
ngx_int_t 
ngx_http_wlr_push_disabled(ngx_conf_t *cf, ngx_http_dummy_loc_conf_t *dlc, 
			   ngx_http_rule_t *curr) {
  ngx_http_rule_t	**dr;
#ifdef whitelist_debug
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "[naxsi] rule %d disabled",
		     curr->wl_id[0]);
#endif
  if (!dlc->disabled_rules)
    dlc->disabled_rules = ngx_array_create(cf->pool, 4, 
					   sizeof(ngx_http_rule_t *));
  if (!dlc->disabled_rules)
    return (NGX_ERROR);
  dr = ngx_array_push(dlc->disabled_rules);
  if (!dr)
    return (NGX_ERROR);
  *dr = (ngx_http_rule_t *) curr;
  return (NGX_OK);
}

/* merge the two rules into father_wl, meaning 
   ids. Not locations, as we are getting rid of it */
ngx_int_t 
ngx_http_wlr_merge(ngx_conf_t *cf, ngx_http_whitelist_rule_t *father_wl, 
		   ngx_http_rule_t *curr) {
  uint i;
  ngx_int_t		*tmp_ptr;
  
  if (!father_wl->ids)
    {
      father_wl->ids = ngx_array_create(cf->pool, 3, sizeof(int));
      if (!father_wl->ids)
	return (NGX_ERROR);
    }
  for (i = 0; curr->wl_id[i] >= 0 ; i++) {
    tmp_ptr = ngx_array_push(father_wl->ids);
    if (!tmp_ptr)
      return (NGX_ERROR);
    *tmp_ptr = curr->wl_id[i];
  }
  return (NGX_OK);
}

/*check rule, returns associed zone, as well as location index.
  location index refers to $URL:bla or $ARGS_VAR:bla */
#define custloc_array(x) ((ngx_http_custom_rule_location_t *) x)

ngx_int_t 
ngx_http_wlr_identify(ngx_conf_t *cf, ngx_http_dummy_loc_conf_t *dlc, 
		      ngx_http_rule_t *curr, int *zone,
		      int *uri_idx, int *name_idx) {
  
  uint	i;

  /*
    identify global match zones (|ARGS|BODY|HEADERS|URL|FILE_EXT)
   */
  if (curr->br->body || curr->br->body_var)
    *zone = BODY;
  else if (curr->br->headers || curr->br->headers_var)
    *zone = HEADERS;
  else if (curr->br->args || curr->br->args_var)
    *zone = ARGS;
  else if (curr->br->url) /*don't assume that named $URL means zone is URL.*/
    *zone = URL;
  else if (curr->br->file_ext)
    *zone = FILE_EXT;
  /*
    if we're facing a WL in the style $URL:/bla|ARGS (or any other zone),
    push it to 
   */
  for (i = 0; i < curr->br->custom_locations->nelts; i++) {
    /*
      locate target URL if exists ($URL:/bla|ARGS) or ($URL:/bla|$ARGS_VAR:foo)
     */
    if (custloc_array(curr->br->custom_locations->elts)[i].specific_url) {
#ifdef whitelist_heavy_debug
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			 "whitelist has URI %V", &(custloc_array(curr->br->custom_locations->elts)[i].target));
#endif
      *uri_idx = i;
    }
    /*
      identify named match zones ($ARGS_VAR:bla|$HEADERS_VAR:bla|$BODY_VAR:bla)
    */
    if (custloc_array(curr->br->custom_locations->elts)[i].body_var) {
#ifdef whitelist_heavy_debug
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			 "whitelist has body_var %V", &(custloc_array(curr->br->custom_locations->elts)[i].target));
#endif
      *name_idx = i;
      *zone = BODY;
    }
    if (custloc_array(curr->br->custom_locations->elts)[i].headers_var) {
#ifdef whitelist_heavy_debug
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			 "whitelist has header_var %V", &(custloc_array(curr->br->custom_locations->elts)[i].target));
#endif
      *name_idx = i;
      *zone = HEADERS;
    }
    if (custloc_array(curr->br->custom_locations->elts)[i].args_var) {
#ifdef whitelist_heavy_debug
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			 "whitelist has arg_var %V", &(custloc_array(curr->br->custom_locations->elts)[i].target));
#endif
      *name_idx = i;
      *zone = ARGS;
    }
  }
  if (*zone == -1)
    return (NGX_ERROR);
  return (NGX_OK);
}


ngx_http_whitelist_rule_t *
ngx_http_wlr_find(ngx_conf_t *cf, ngx_http_dummy_loc_conf_t *dlc,
		  ngx_http_rule_t *curr, int zone, int uri_idx,
		  int name_idx, char **fullname) {
  uint i;
  
  /* Create unique string for rule, and try to find it in existing rules.*/
  /*name AND uri*/
  
  if (uri_idx != -1 && name_idx != -1) {
#ifdef whitelist_heavy_debug
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
		       "whitelist has uri + name");
#endif
    *fullname = ngx_pcalloc(cf->pool, custloc_array(curr->br->custom_locations->elts)[name_idx].target.len +
			    custloc_array(curr->br->custom_locations->elts)[uri_idx].target.len + 2);
    strncat(*fullname, (const char *) custloc_array(curr->br->custom_locations->elts)[uri_idx].target.data, 
	    custloc_array(curr->br->custom_locations->elts)[uri_idx].target.len);
    strncat(*fullname, (const char *) "#", 1);
    strncat(*fullname, (const char *) custloc_array(curr->br->custom_locations->elts)[name_idx].target.data, 
	    custloc_array(curr->br->custom_locations->elts)[name_idx].target.len);
  }
  /* only uri */
  else if (uri_idx != -1 && name_idx == -1) {
#ifdef whitelist_heavy_debug
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
		       "whitelist has uri");
#endif
    *fullname = ngx_pcalloc(cf->pool, custloc_array(curr->br->custom_locations->elts)[uri_idx].target.len + 1);
    strncat(*fullname, (const char *) custloc_array(curr->br->custom_locations->elts)[uri_idx].target.data, 
	    custloc_array(curr->br->custom_locations->elts)[uri_idx].target.len);
  }
  /* only name */
  else if (name_idx != -1) {
#ifdef whitelist_heavy_debug
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
		       "whitelist has name");
#endif
    *fullname = ngx_pcalloc(cf->pool, custloc_array(curr->br->custom_locations->elts)[name_idx].target.len + 1);
    strncat(*fullname, (const char *) custloc_array(curr->br->custom_locations->elts)[name_idx].target.data, 
	    custloc_array(curr->br->custom_locations->elts)[name_idx].target.len);
  }
  /* problem houston */
  else
    return (NULL);
  
  for (i = 0; i < dlc->tmp_wlr->nelts; i++)
    if (!strcmp((const char *)*fullname, (const char *)((ngx_http_whitelist_rule_t *) dlc->tmp_wlr->elts)[i].name->data) && 
	((ngx_http_whitelist_rule_t *) dlc->tmp_wlr->elts)[i].zone == (uint) zone)
      {
#ifdef whitelist_heavy_debug
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			   "found existing 'same' WL : %V", ((ngx_http_whitelist_rule_t *) dlc->tmp_wlr->elts)[i].name);
#endif
	return (&((ngx_http_whitelist_rule_t *)dlc->tmp_wlr->elts)[i]);
      }
  return (NULL);
}

#define httprule_array(x) ((ngx_http_rule_t *) x)


ngx_int_t
ngx_http_wlr_finalize_hashtables(ngx_conf_t *cf, ngx_http_dummy_loc_conf_t  *dlc) {
  int get_sz = 0, headers_sz = 0, body_sz = 0, uri_sz = 0;
  ngx_array_t *get_ar = NULL, *headers_ar = NULL, *body_ar = NULL, *uri_ar = NULL;
  ngx_hash_key_t *arr_node;
  ngx_hash_init_t hash_init;
  uint i, z;
  
#ifdef whitelist_heavy_debug
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
		     "finalizing hashtables");
#endif
  
  for (i = 0; i < dlc->tmp_wlr->nelts; i++) {
    switch (((ngx_http_whitelist_rule_t *) dlc->tmp_wlr->elts)[i].zone) {
    case FILE_EXT:
    case BODY:
      body_sz++;
      break;
    case HEADERS:
      headers_sz++;
      break;
    case URL:
      uri_sz++;
      break;
    case ARGS:
      get_sz++;
      break;
    case UNKNOWN:
    default:
      return (NGX_ERROR);
    }
  }
#ifdef whitelist_heavy_debug
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
		     "nb items : body:%d headers:%d uri:%d get:%d",
		     body_sz, headers_sz, uri_sz, get_sz);
#endif

  if (get_sz)
    get_ar = ngx_array_create(cf->pool, get_sz, sizeof(ngx_hash_key_t));
  if (headers_sz)
    headers_ar = ngx_array_create(cf->pool, headers_sz, sizeof(ngx_hash_key_t));
  if (body_sz)
    body_ar = ngx_array_create(cf->pool, body_sz, sizeof(ngx_hash_key_t));
  if (uri_sz)
    uri_ar = ngx_array_create(cf->pool, uri_sz, sizeof(ngx_hash_key_t));
  for (i = 0; i < dlc->tmp_wlr->nelts; i++) {
    switch (((ngx_http_whitelist_rule_t *) dlc->tmp_wlr->elts)[i].zone) {
    case FILE_EXT:
    case BODY:
      arr_node = (ngx_hash_key_t*) ngx_array_push(body_ar);
      break;
    case HEADERS:
      arr_node = (ngx_hash_key_t*) ngx_array_push(headers_ar);
      break;
    case URL:
      arr_node = (ngx_hash_key_t*) ngx_array_push(uri_ar);
      break;
    case ARGS:
      arr_node = (ngx_hash_key_t*) ngx_array_push(get_ar);
      break;
    default:
      return (NGX_ERROR);
    }
    ngx_memset(arr_node, 0, sizeof(ngx_hash_key_t));
    arr_node->key = *(((ngx_http_whitelist_rule_t *) dlc->tmp_wlr->elts)[i].name);
    arr_node->key_hash = ngx_hash_key_lc(((ngx_http_whitelist_rule_t *) dlc->tmp_wlr->elts)[i].name->data, 
					 ((ngx_http_whitelist_rule_t *) dlc->tmp_wlr->elts)[i].name->len);
    arr_node->value = (void *) &(((ngx_http_whitelist_rule_t *) dlc->tmp_wlr->elts)[i]);
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "pushing new WL, zone:%d, target:%V, %d IDs",
		       ((ngx_http_whitelist_rule_t *) dlc->tmp_wlr->elts)[i].zone ,  ((ngx_http_whitelist_rule_t *) dlc->tmp_wlr->elts)[i].name,
		        ((ngx_http_whitelist_rule_t *) dlc->tmp_wlr->elts)[i].ids->nelts);
    
    for (z = 0; z < ((ngx_http_whitelist_rule_t *) dlc->tmp_wlr->elts)[i].ids->nelts; z++)
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "id:%d",
    			 ((int *)((ngx_http_whitelist_rule_t *) dlc->tmp_wlr->elts)[i].ids->elts)[z]);
    
  }
  hash_init.key = &ngx_hash_key_lc;
  hash_init.pool = cf->pool;
  hash_init.temp_pool = NULL;
  hash_init.max_size  = 1024;
  hash_init.bucket_size = 512;
  
  if (body_ar) {
    dlc->wlr_body_hash =  (ngx_hash_t*) ngx_pcalloc(cf->pool, sizeof(ngx_hash_t));
    hash_init.hash = dlc->wlr_body_hash;
    hash_init.name = "wlr_body_hash";
    if (ngx_hash_init(&hash_init, (ngx_hash_key_t*) body_ar->elts, 
		      body_ar->nelts) != NGX_OK) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "$BODY hashtable init failed");
      return (NGX_ERROR);
    }

#ifdef whitelist_debug
    else
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "$BODY hashtable init successed !");
#endif
  }
  if (uri_ar) {
    dlc->wlr_url_hash =  (ngx_hash_t*) ngx_pcalloc(cf->pool, sizeof(ngx_hash_t));
    hash_init.hash = dlc->wlr_url_hash;
    hash_init.name = "wlr_url_hash";
    if (ngx_hash_init(&hash_init, (ngx_hash_key_t*) uri_ar->elts, 
		      uri_ar->nelts) != NGX_OK) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "$URL hashtable init failed");
      return (NGX_ERROR);
    }
#ifdef whitelist_debug
    else
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "$URL hashtable init successed !");
#endif
  }
  if (get_ar) {
    dlc->wlr_args_hash =  (ngx_hash_t*) ngx_pcalloc(cf->pool, sizeof(ngx_hash_t));
    hash_init.hash = dlc->wlr_args_hash;
    hash_init.name = "wlr_args_hash";
    if (ngx_hash_init(&hash_init, (ngx_hash_key_t*) get_ar->elts, 
		      get_ar->nelts) != NGX_OK) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "$ARGS hashtable init failed");
      return (NGX_ERROR);
    }
#ifdef whitelist_debug
    else
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "$ARGS hashtable init successed %d !",
			 dlc->wlr_args_hash->size);
#endif

  }
  if (headers_ar) {
    dlc->wlr_headers_hash =  (ngx_hash_t*) ngx_pcalloc(cf->pool, sizeof(ngx_hash_t));
    hash_init.hash = dlc->wlr_headers_hash;
    hash_init.name = "wlr_headers_hash";
    if (ngx_hash_init(&hash_init, (ngx_hash_key_t*) headers_ar->elts, 
		      headers_ar->nelts) != NGX_OK) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "$HEADERS hashtable init failed");
      return (NGX_ERROR);
    }
#ifdef whitelist_debug
    else
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "$HEADERS hashtable init successed %d !",
			 dlc->wlr_headers_hash->size);
#endif

  }
  return (NGX_OK);
}

ngx_int_t
ngx_http_dummy_create_hashtables_n(ngx_http_dummy_loc_conf_t *dlc, 
				   ngx_conf_t *cf)
{
  int				zone, uri_idx, name_idx, ret;
  ngx_http_rule_t		*curr_r/*, *father_r*/;
  ngx_http_whitelist_rule_t	*father_wlr;
  unsigned char			*fullname;
  uint	i;
#ifdef whitelist_heavy_debug
  ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
		     "Building whitelist hashtables, %d items in list",
		     dlc->whitelist_rules->nelts);
#endif
  if (!dlc->whitelist_rules || dlc->whitelist_rules->nelts < 1) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
		       "No whitelist registred, but it's your call.");    
    return (NGX_OK);
  }
  dlc->tmp_wlr = ngx_array_create(cf->pool, dlc->whitelist_rules->nelts,
  				  sizeof(ngx_http_whitelist_rule_t));
  /* iterate through each stored whitelist rule. */
  for (i = 0; i < dlc->whitelist_rules->nelts; i++) {
    uri_idx = name_idx = zone = -1;
    /*a whitelist is in fact just another basic_rule_t */
    curr_r = &(httprule_array(dlc->whitelist_rules->elts)[i]);
#ifdef whitelist_heavy_debug
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
		       "Processing wl %d/%p", i, curr_r);
#endif
    /*no custom location at all means that the rule is disabled */
    if (!curr_r->br->custom_locations) {
#ifdef whitelist_heavy_debug
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			 "WL %d is a disable rule.", i);
#endif
      if (ngx_http_wlr_push_disabled(cf, dlc, curr_r) == NGX_ERROR)
	return (NGX_ERROR);
      continue;
    }
/* #ifdef whitelist_heavy_debug */
/*     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,  */
/* 		       "uri idx:%d, name idx:%d", uri_idx, name_idx); */
/* #endif */
    
    ret = ngx_http_wlr_identify(cf, dlc, curr_r, &zone, &uri_idx, &name_idx);
    if (ret != NGX_OK)
      {
	ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			   "naxsi internal error in wlr_identify.");
	return (NGX_ERROR);
      }
/* #ifdef whitelist_heavy_debug */
/*     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,  */
/* 		       "uri idx:%d, name idx:%d", uri_idx, name_idx); */
/* #endif */
    father_wlr = ngx_http_wlr_find(cf, dlc, curr_r, zone, uri_idx, name_idx, (char **) &fullname);
    if (!father_wlr) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, 
			 "creating fresh WL [%s].", fullname);
      /* creates a new whitelist rule in the right place.
	 setup name and zone, create a new (empty) whitelist_location, as well
	 as a new (empty) id aray. */
      father_wlr = ngx_array_push(dlc->tmp_wlr);
      if (!father_wlr)
	return (NGX_ERROR);
      memset(father_wlr, 0, sizeof(ngx_http_whitelist_rule_t));
      father_wlr->name = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
      if (!father_wlr->name)
	return (NGX_ERROR);
      father_wlr->name->len = strlen((const char *) fullname);
      father_wlr->name->data = fullname;
      /* father_wlr->name->data = ngx_pcalloc(cf->pool,  father_wlr->name->len+1); */
      /* ngx_memcpy(father_wlr->name->data, fullname, father_wlr->name->len); */
      father_wlr->zone = zone;
      //ngx_pfree(cf->pool, fullname);
    }
    /*merges the two whitelist rules together, including custom_locations. */
    if (ngx_http_wlr_merge(cf, father_wlr, curr_r) != NGX_OK)
      return (NGX_ERROR);
    //ngx_pfree(cf->pool, curr_r);
  }
  
  /* and finally, build the hashtables for various zones. */
  if (ngx_http_wlr_finalize_hashtables(cf, dlc) != NGX_OK)
    return (NGX_ERROR);
  //ngx_pfree(cf->pool, dlc->whitelist_rules);
  return (NGX_OK);
}

