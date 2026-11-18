# Offline USB Descriptor Framing

This R0 component supplies a narrow part of `AOE-GD-D24-S03`. It walks a bounded caller-provided byte stream by each descriptor's `bLength` and records `bDescriptorType`, preserving unknown types without interpreting their payload. A short header, length below two bytes or length beyond the supplied stream is a review candidate only when the capture is declared complete. The [Linux kernel's FunctionFS descriptor documentation](https://docs.kernel.org/next/usb/functionfs-desc.html) describes this framing, and the [USB-IF specification library](https://www.usb.org/document-library/usb-20-specification) provides the protocol context.

The input is not a device capture authenticated by this component. It does not parse HID reports or class-specific payloads, determine whether a descriptor was accepted by a host, or contact a USB device, controller or removable medium.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-usb-descriptor-framing-component.json`](../examples/offline-usb-descriptor-framing-component.json).
