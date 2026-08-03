/*
 * handle_burstgen.h  --  public interface for mode=burstgen
 *
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef _HANDLE_BURSTGEN_H_
#define _HANDLE_BURSTGEN_H_

#include "task_base.h"

/* Print normal-phase and burst-phase TX counts to the PROX log/socket.
 * Called by cmd_parser when "burstgen stats <core> <task>" is received. */
void task_burstgen_print_stats(struct task_base *tbase);

#endif /* _HANDLE_BURSTGEN_H_ */
