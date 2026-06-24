/*
 * handle_flowgen.h  --  public interface for mode=flowgen
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef _HANDLE_FLOWGEN_H_
#define _HANDLE_FLOWGEN_H_

#include "task_base.h"

/* Print per-interval TX stats to the PROX log/socket.
 * Called by cmd_parser when "flowgen stats <core> <task>" is received. */
void task_flowgen_print_stats(struct task_base *tbase);

#endif /* _HANDLE_FLOWGEN_H_ */
