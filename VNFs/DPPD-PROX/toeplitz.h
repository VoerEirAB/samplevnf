/*
// Copyright (c) 2010-2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef _TOEPLITZ_H_
#define _TOEPLITZ_H_

#define TOEPLITZ_KEY_LEN	40
#define TOEPLITZ_KEY_LEN_52     52
extern uint8_t toeplitz_init_key[TOEPLITZ_KEY_LEN];

extern uint8_t toeplitz_init_key_52[TOEPLITZ_KEY_LEN_52];
uint32_t toeplitz_hash(uint8_t *buf_p, int buflen);
#endif
