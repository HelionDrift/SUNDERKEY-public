# Offline ROS 2 Security Declaration

This R0 component supports a narrow part of `AOE-GD-D19-S18`. It compares caller-supplied protected-topic intent with declared security enablement, strict enforcement, unauthenticated-participant allowance, and join access control. A review candidate requires complete context and an explicitly required authentication boundary with at least one declared control gap. The [ROS 2 DDS-Security design](https://design.ros2.org/articles/ros2_dds_security.html) explains governance, permissions, and enforcement modes; the [ROS 2 threat model](https://design.ros2.org/articles/ros2_threat_model.html) discusses participant admission controls.

The component does not parse signed DDS governance or permissions, inspect certificates, launch nodes, or contact a robot. Topic IDs are opaque caller labels, not parsed ROS topic names. A declared gap does not prove effective access or a usable exploit path.

The unsigned report requires separately retained original-model replay and grants no finding, qualification, or positive-use authority.

Example: [`examples/offline-ros2-security-declaration-component.json`](../examples/offline-ros2-security-declaration-component.json).
