/*
 * handle_flowcount.h  --  public interface for mode=flowcount
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef _HANDLE_FLOWCOUNT_H_
#define _HANDLE_FLOWCOUNT_H_

#include "task_base.h"

/* Print per-interval RX stats to the PROX log/socket.
 * Called by cmd_parser when "flowcount stats <core> <task>" is received. */
void task_flowcount_print_stats(struct task_base *tbase);

#endif /* _HANDLE_FLOWCOUNT_H_ */
