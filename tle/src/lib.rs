/*
 * Copyright 2024 by Ideal Labs, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#![no_std]
#![warn(
	unused,
	future_incompatible,
	nonstandard_style,
	rust_2018_idioms,
	rust_2021_compatibility
)]
#![allow(
	clippy::op_ref,
	clippy::suspicious_op_assign_impl,
	clippy::type_complexity,
	clippy::should_implement_trait
)]
#![deny(unsafe_code)]

extern crate alloc;

pub mod curves;
pub mod ibe;
pub mod stream_ciphers;
pub mod tlock;
