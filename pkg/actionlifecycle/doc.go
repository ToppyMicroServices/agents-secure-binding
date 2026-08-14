// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

// Package actionlifecycle implements the repository's durable long-running
// Action state model. It is transport independent: ROS 2 Actions supply the
// goal/feedback/cancel/result model, while an application binding supplies the
// wire protocol and durable Store.
package actionlifecycle
