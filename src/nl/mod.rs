// socketcan/src/nl/mod.rs
//
// Netlink access to the SocketCAN interfaces.
//
// This file is part of the Rust 'socketcan-rs' library.
//
// Licensed under the MIT license:
//   <LICENSE or http://opensource.org/licenses/MIT>
// This file may not be copied, modified, or distributed except according
// to those terms.

//! CAN Netlink access
//!
//! The netlink module contains the netlink-based management capabilities of
//! the socketcan crate.
//!
//! For SocketCAN, netlink is the primary way for a user-space application to
//! query or set the parameters of a CAN interface, such as the bitrate, the
//! control mode bits, and so forth. It also allows the application to get
//! statistics from the interface and send commands to it, including
//! performing a bus restart.
//!
//1 Netlink is a socket-based mechanism, similar to Unix-domain sockets, which
//! allows a user-space program communicate with the kernel.
//!
//! Unfortunately, the SocketCAN netlink API does not appear to be documented
//! _anywhere_. The netlink functional summary on the SocketCAN page is here:
//!
//! <https://www.kernel.org/doc/html/latest/networking/can.html#netlink-interface-to-set-get-devices-properties>
//!
//! The CAN netlink header file for the Linux kernel has the definition of
//! the constants and data structures that are sent back and forth to the
//! kernel over netlink. It can be found in the Linux sources here:
//!
//! <https://github.com/torvalds/linux/blob/master/include/uapi/linux/can/netlink.h?ts=4>
//!
//! The corresponding kernel code that receives and processes messages from
//! userspace is useful to help figure out what the kernel expects. It's here:
//!
//! <https://github.com/torvalds/linux/blob/master/drivers/net/can/dev/netlink.c?ts=4>
//! <https://github.com/torvalds/linux/blob/master/drivers/net/can/dev/dev.c?ts=4>
//!
//! The main Linux user-space client to communicate with network interfaces,
//! including CAN is _iproute2_. The CAN-specific code for it is here:
//!
//! <https://github.com/iproute2/iproute2/blob/main/ip/iplink_can.c?ts=4>
//!
//! There is also a C user-space library for SocketCAN, which primarily
//! deals with the Netlink interface. There are several forks, but one of
//! the later ones with updated documents is here:
//!
//! <https://github.com/lalten/libsocketcan>
//!

use neli::{
    attr::Attribute,
    consts::{
        nl::NlmF,
        rtnl::{Arphrd, Iff, Ifla, IflaInfo, RtAddrFamily, Rtm},
        socket::NlFamily,
    },
    err::{BuilderError, DeError, RouterError, SocketError},
    nl::{NlPayload, Nlmsghdr},
    router::synchronous::NlRouter,
    rtnl::{Ifinfomsg, IfinfomsgBuilder, Rtattr, RtattrBuilder},
    types::{Buffer, RtBuffer},
    utils::Groups,
    FromBytes, Size, ToBytes,
};
use nix::{self, net::if_::if_nametoindex, unistd};
use rt::{can_ctrlmode, IflaCan, IflaCanCtrlMode};
use std::{ffi::CStr, fmt::Debug, os::raw::c_uint};

/// Low-level Netlink CAN struct bindings.
mod rt;

pub use rt::CanState;

/// A result for Netlink errors.
type NlResult<T> = Result<T, RouterError<Rtm, Ifinfomsg>>;

/// CAN bit-timing parameters
pub type CanBitTiming = rt::can_bittiming;
/// CAN bit-timing const parameters
pub type CanBitTimingConst = rt::can_bittiming_const;
/// CAN clock parameter
pub type CanClock = rt::can_clock;
/// CAN bus error counters
pub type CanBerrCounter = rt::can_berr_counter;

/// The details of the interface which can be obtained with the
/// `CanInterface::details()` function.
#[allow(missing_copy_implementations)]
#[derive(Debug, Default, Clone)]
pub struct InterfaceDetails {
    /// The name of the interface
    pub name: Option<String>,
    /// The index of the interface
    pub index: c_uint,
    /// Whether the interface is currently up
    pub is_up: bool,
    /// The MTU size of the interface (Standard or FD frames support)
    pub mtu: Option<Mtu>,
    /// The CAN-specific parameters for the interface
    pub can: InterfaceCanParams,
}

impl InterfaceDetails {
    /// Creates a new set of interface details with the specified `index`.
    pub fn new(index: c_uint) -> Self {
        Self {
            index,
            ..Self::default()
        }
    }
}

/// The MTU size for the interface
///
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Mtu {
    /// Standard CAN frame, 8-byte data (16-byte total)
    Standard = 16,
    /// FD CAN frame, 64-byte data (64-byte total)
    Fd = 72,
}

impl TryFrom<u32> for Mtu {
    type Error = std::io::Error;

    fn try_from(val: u32) -> Result<Self, Self::Error> {
        match val {
            16 => Ok(Mtu::Standard),
            72 => Ok(Mtu::Fd),
            _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
        }
    }
}

/// The CAN-specific parameters for the interface.
#[allow(missing_copy_implementations)]
#[derive(Debug, Default, Clone)]
pub struct InterfaceCanParams {
    /// The CAN bit timing parameters
    pub bit_timing: Option<CanBitTiming>,
    /// The bit timing const parameters
    pub bit_timing_const: Option<CanBitTimingConst>,
    /// The CAN clock parameters (read only)
    pub clock: Option<CanClock>,
    /// The CAN bus state (read-only)
    pub state: Option<CanState>,
    /// The automatic restart time (in millisec)
    /// Zero means auto-restart is disabled.
    pub restart_ms: Option<u32>,
    /// The bit error counter (read-only)
    pub berr_counter: Option<CanBerrCounter>,
    /// The control mode bits
    pub ctrl_mode: Option<CanCtrlModes>,
    /// The supported control mode bits
    pub ctrl_mode_supported: Option<CanCtrlModes>,
    /// The FD data bit timing
    pub data_bit_timing: Option<CanBitTiming>,
    /// The FD data bit timing const parameters
    pub data_bit_timing_const: Option<CanBitTimingConst>,
    /// The CANbus termination resistance
    pub termination: Option<u16>,
}

impl TryFrom<&Rtattr<Ifla, Buffer>> for InterfaceCanParams {
    type Error = DeError;

    /// Try to parse the CAN parameters out of a Linkinfo attribute
    fn try_from(link_info: &Rtattr<Ifla, Buffer>) -> Result<Self, Self::Error> {
        let mut params = Self::default();

        for info in link_info.get_attr_handle::<IflaInfo>()?.get_attrs() {
            if *info.rta_type() == IflaInfo::Data {
                for attr in info.get_attr_handle::<IflaCan>()?.get_attrs() {
                    match attr.rta_type() {
                        IflaCan::BitTiming => {
                            params.bit_timing = Some(attr.get_payload_as::<CanBitTiming>()?);
                        }
                        IflaCan::BitTimingConst => {
                            params.bit_timing_const =
                                Some(attr.get_payload_as::<CanBitTimingConst>()?);
                        }
                        IflaCan::Clock => {
                            params.clock = Some(attr.get_payload_as::<CanClock>()?);
                        }
                        IflaCan::State => {
                            params.state = CanState::try_from(attr.get_payload_as::<u32>()?).ok();
                        }
                        IflaCan::CtrlMode => {
                            let ctrl_mode = attr.get_payload_as::<can_ctrlmode>()?;
                            params.ctrl_mode = Some(CanCtrlModes(ctrl_mode));
                        }
                        IflaCan::RestartMs => {
                            params.restart_ms = Some(attr.get_payload_as::<u32>()?);
                        }
                        IflaCan::BerrCounter => {
                            params.berr_counter = Some(attr.get_payload_as::<CanBerrCounter>()?);
                        }
                        IflaCan::DataBitTiming => {
                            params.data_bit_timing = Some(attr.get_payload_as::<CanBitTiming>()?);
                        }
                        IflaCan::DataBitTimingConst => {
                            params.data_bit_timing_const =
                                Some(attr.get_payload_as::<CanBitTimingConst>()?);
                        }
                        IflaCan::Termination => {
                            params.termination = Some(attr.get_payload_as::<u16>()?);
                        }
                        IflaCan::CtrlModeExt => {
                            for ctrlmode_attr in
                                attr.get_attr_handle::<IflaCanCtrlMode>()?.get_attrs()
                            {
                                match ctrlmode_attr.rta_type() {
                                    IflaCanCtrlMode::Supported => {
                                        let ctrl_mode = attr.get_payload_as::<can_ctrlmode>()?;
                                        params.ctrl_mode_supported = Some(CanCtrlModes(ctrl_mode));
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => (),
                    }
                }
            }
        }
        Ok(params)
    }
}

impl TryFrom<&InterfaceCanParams> for RtBuffer<Ifla, Buffer> {
    type Error = SocketError;

    /// Try to parse the CAN parameters into a NetLink buffer
    fn try_from(params: &InterfaceCanParams) -> Result<Self, Self::Error> {
        let mut rtattrs: RtBuffer<Ifla, Buffer> = RtBuffer::new();
        let mut data = RtattrBuilder::default()
            .rta_type(IflaInfo::Data)
            .rta_payload(Buffer::new())
            .build()?;

        // TODO: Set the rest of the writable params
        if let Some(bt) = params.bit_timing {
            data = data.nest(
                &RtattrBuilder::default()
                    .rta_type(IflaCan::BitTiming)
                    .rta_payload(bt)
                    .build()?,
            )?;
        }
        if let Some(r) = params.restart_ms {
            data = data.nest(
                &RtattrBuilder::default()
                    .rta_type(IflaCan::RestartMs)
                    .rta_payload(&r.to_ne_bytes()[..])
                    .build()?,
            )?;
        }
        if let Some(cm) = params.ctrl_mode {
            data = data.nest(
                &RtattrBuilder::<_, can_ctrlmode>::default()
                    .rta_type(IflaCan::CtrlMode)
                    .rta_payload(cm.into())
                    .build()?,
            )?;
        }
        if let Some(dbt) = params.data_bit_timing {
            data = data.nest(
                &RtattrBuilder::default()
                    .rta_type(IflaCan::DataBitTiming)
                    .rta_payload(dbt)
                    .build()?,
            )?;
        }
        if let Some(t) = params.termination {
            data = data.nest(
                &RtattrBuilder::default()
                    .rta_type(IflaCan::Termination)
                    .rta_payload(t)
                    .build()?,
            )?;
        }

        let link_info = RtattrBuilder::default()
            .rta_type(Ifla::Linkinfo)
            .rta_payload(Buffer::new())
            .build()?
            .nest(
                &RtattrBuilder::default()
                    .rta_type(IflaInfo::Kind)
                    .rta_payload("can")
                    .build()?,
            )?
            .nest(&data)?;

        rtattrs.push(link_info);
        Ok(rtattrs)
    }
}

// ===== CanCtrlMode(s) =====

///
/// CAN control modes
///
/// Note that these correspond to the bit _numbers_ for the control mode bits.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CanCtrlMode {
    /// Loopback mode
    Loopback,
    /// Listen-only mode
    ListenOnly,
    /// Triple sampling mode
    TripleSampling,
    /// One-Shot mode
    OneShot,
    /// Bus-error reporting
    BerrReporting,
    /// CAN FD mode
    Fd,
    /// Ignore missing CAN ACKs
    PresumeAck,
    /// CAN FD in non-ISO mode
    NonIso,
    /// Classic CAN DLC option
    CcLen8Dlc,
}

impl CanCtrlMode {
    /// Get the mask for the specific control mode
    pub fn mask(&self) -> u32 {
        1u32 << (*self as u32)
    }
}

/// The collection of control modes
#[derive(Debug, Default, Clone, Copy)]
pub struct CanCtrlModes(can_ctrlmode);

impl CanCtrlModes {
    /// Create a set of CAN control modes from a mask and set of flags.
    pub fn new(mask: u32, flags: u32) -> Self {
        Self(can_ctrlmode { mask, flags })
    }

    /// Create the set of mode flags for a single mode
    pub fn from_mode(mode: CanCtrlMode, on: bool) -> Self {
        let mask = mode.mask();
        let flags = if on { mask } else { 0 };
        Self::new(mask, flags)
    }

    /// Adds a mode flag to the existing set of modes.
    pub fn add(&mut self, mode: CanCtrlMode, on: bool) {
        let mask = mode.mask();
        self.0.mask |= mask;
        if on {
            self.0.flags |= mask;
        }
    }

    /// Clears all of the mode flags in the collection
    #[inline]
    pub fn clear(&mut self) {
        self.0 = can_ctrlmode::default();
    }

    /// Test if this CanCtrlModes has a specific `mode` turned on
    ///
    /// This can be useful for inspecting an [InterfaceCanParams] obtained from
    /// [CanInterface::details].
    ///
    /// # Examples
    ///
    /// ```
    /// use socketcan::nl::CanCtrlModes;
    /// use socketcan::CanCtrlMode;
    ///
    /// let modes = CanCtrlModes::new(0x20, 0x20); // This is bit 5 (CanCtrlMode::Fd)
    /// assert_eq!(modes.has_mode(CanCtrlMode::Fd), true);
    /// assert_eq!(modes.has_mode(CanCtrlMode::ListenOnly), false);
    /// ```
    #[inline]
    pub fn has_mode(&self, mode: CanCtrlMode) -> bool {
        (mode.mask() & self.0.flags) != 0
    }
}

impl From<can_ctrlmode> for CanCtrlModes {
    fn from(mode: can_ctrlmode) -> Self {
        Self(mode)
    }
}

impl From<CanCtrlModes> for can_ctrlmode {
    fn from(mode: CanCtrlModes) -> Self {
        mode.0
    }
}

// ===== CanInterface =====

/// SocketCAN Netlink CanInterface
///
/// Controlled through the kernel's Netlink interface, CAN devices can be
/// brought up or down or configured or queried through this.
///
/// Note while that this API is designed in an RAII-fashion, it cannot really
/// make the same guarantees: It is entirely possible for another user/process
/// to modify, remove and re-add an interface while you are holding this object
/// with a reference to it.
///
/// Some actions possible on this interface require the process/user to have
/// the `CAP_NET_ADMIN` capability, like the root user does. This is
/// indicated by their documentation starting with "PRIVILEGED:".
#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub struct CanInterface {
    if_index: c_uint,
}

impl CanInterface {
    /// Open a CAN interface by name.
    ///
    /// Similar to `open_iface`, but looks up the device by name instead of
    /// the interface index.
    pub fn open(ifname: &str) -> Result<Self, nix::Error> {
        let if_index = if_nametoindex(ifname)?;
        Ok(Self::open_iface(if_index))
    }

    /// Open a CAN interface.
    ///
    /// Creates a new `CanInterface` instance.
    ///
    /// Note that no actual "opening" or checks are performed when calling
    /// this function, nor does it test to determine if the interface with
    /// the specified index actually exists.
    pub fn open_iface(if_index: u32) -> Self {
        let if_index = if_index as c_uint;
        Self { if_index }
    }

    /// Creates an `Ifinfomsg` for this CAN interface from a buffer
    fn info_msg(&self, buf: RtBuffer<Ifla, Buffer>) -> Result<Ifinfomsg, BuilderError> {
        Ok(IfinfomsgBuilder::default()
            .ifi_index(self.if_index as i32)
            .rtattrs(buf)
            .build()?)
    }

    /// Sends an info message to the kernel.
    fn send_info_msg(
        msg_type: Rtm,
        info: Ifinfomsg,
        additional_flags: NlmF,
    ) -> Result<(), RouterError<Rtm, Ifinfomsg>> {
        let nl = Self::open_router().map_err(|err| err.to_typed().unwrap_or_else(|err| err))?;

        for response in nl.send(
            msg_type,
            NlmF::REQUEST | NlmF::ACK | additional_flags,
            NlPayload::Payload(info),
        )? {
            if let Some(err) = response?.get_err() {
                Err(RouterError::Nlmsgerr(err))?;
            }
        }

        Ok(())
    }

    /// Opens a new netlink socket router, bound to this process' PID.
    fn open_router() -> Result<NlRouter, RouterError<u16, Buffer>> {
        // retrieve PID
        let pid = unistd::Pid::this().as_raw() as u32;

        // groups is empty, because we want no notifications
        Ok(NlRouter::connect(NlFamily::Route, Some(pid), Groups::empty())?.0)
    }

    /// Sends a query to the kernel and returns the response info message
    /// to the caller.
    fn query_details(
        &self,
    ) -> Result<Option<Nlmsghdr<Rtm, Ifinfomsg>>, RouterError<Rtm, Ifinfomsg>> {
        let nl = Self::open_router().map_err(|err| err.to_typed().unwrap_or_else(|err| err))?;

        let info = self.info_msg({
            let mut buffer = RtBuffer::new();
            buffer.push(
                RtattrBuilder::default()
                    .rta_type(Ifla::ExtMask)
                    .rta_payload(rt::EXT_FILTER_VF)
                    .build()?,
            );
            buffer
        })?;

        for response in nl.send(Rtm::Getlink, NlmF::REQUEST, NlPayload::Payload(info))? {
            return Ok(Some(response?));
        }

        return Ok(None);
    }

    /// Bring down this interface.
    ///
    /// Use a netlink control socket to set the interface status to "down".
    pub fn bring_down(&self) -> NlResult<()> {
        // Specific iface down info
        let info = IfinfomsgBuilder::default()
            .ifi_index(self.if_index as i32)
            .down()
            .build()?;

        Self::send_info_msg(Rtm::Newlink, info, NlmF::empty())
    }

    /// Bring up this interface
    ///
    /// Brings the interface up by settings its "up" flag enabled via netlink.
    pub fn bring_up(&self) -> NlResult<()> {
        // Specific iface up info
        let info = IfinfomsgBuilder::default()
            .ifi_index(self.if_index as i32)
            .up()
            .build()?;

        Self::send_info_msg(Rtm::Newlink, info, NlmF::empty())
    }

    /// Create a virtual CAN (VCAN) interface.
    ///
    /// Useful for testing applications when a physical CAN interface and
    /// bus is not available.
    ///
    /// Note that the length of the name is capped by ```libc::IFNAMSIZ```.
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    pub fn create_vcan(name: &str, index: Option<u32>) -> NlResult<Self> {
        Self::create(name, index, "vcan")
    }

    /// Create an interface of the given kind.
    ///
    /// Note that the length of the name is capped by ```libc::IFNAMSIZ```.
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    pub fn create<I>(name: &str, index: I, kind: &str) -> NlResult<Self>
    where
        I: Into<Option<u32>>,
    {
        if name.len() > libc::IFNAMSIZ {
            return Err(RouterError::new("Interface name too long"));
        }
        let index = index.into();

        let info = IfinfomsgBuilder::default()
            .ifi_family(RtAddrFamily::Unspecified)
            .ifi_type(Arphrd::Netrom)
            .ifi_index(index.unwrap_or_default() as i32)
            .rtattrs({
                let mut buffer = RtBuffer::new();
                buffer.push(
                    RtattrBuilder::default()
                        .rta_type(Ifla::Ifname)
                        .rta_payload(name)
                        .build()?,
                );
                let linkinfo = RtattrBuilder::default()
                    .rta_type(Ifla::Linkinfo)
                    .rta_payload(Vec::<u8>::new())
                    .build()?
                    .nest(
                        &RtattrBuilder::default()
                            .rta_type(IflaInfo::Kind)
                            .rta_payload(kind)
                            .build()?,
                    )
                    .map_err(|err| RouterError::Socket(SocketError::Ser(err)))?;
                buffer.push(linkinfo);
                buffer
            })
            .build()?;

        Self::send_info_msg(Rtm::Newlink, info, NlmF::CREATE | NlmF::EXCL)?;

        if let Some(if_index) = index {
            Ok(Self { if_index })
        } else {
            // Unfortunately netlink does not return the the if_index assigned to the interface.
            if let Ok(if_index) = if_nametoindex(name) {
                Ok(Self { if_index })
            } else {
                Err(RouterError::new(
                    "Interface must have been deleted between request and this if_nametoindex",
                ))
            }
        }
    }

    /// Delete the interface.
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    pub fn delete(self) -> Result<(), (Self, RouterError<Rtm, Ifinfomsg>)> {
        match self.info_msg(RtBuffer::new()) {
            Ok(info) => match Self::send_info_msg(Rtm::Dellink, info, NlmF::empty()) {
                Ok(()) => Ok(()),
                Err(err) => Err((self, err)),
            },
            Err(err) => Err((self, err.into())),
        }
    }

    /// Attempt to query detailed information on the interface.
    pub fn details(&self) -> NlResult<InterfaceDetails> {
        match self.query_details()? {
            Some(msg_hdr) => {
                let mut info = InterfaceDetails::new(self.if_index);

                if let Some(payload) = msg_hdr.get_payload() {
                    info.is_up = payload.ifi_flags().contains(Iff::UP);

                    for attr in payload.rtattrs().iter() {
                        match attr.rta_type() {
                            Ifla::Ifname => {
                                // Note: Use `CStr::from_bytes_until_nul` when MSRV >= 1.69
                                info.name = CStr::from_bytes_with_nul(attr.rta_payload().as_ref())
                                    .map(|s| s.to_string_lossy().into_owned())
                                    .ok();
                            }
                            Ifla::Mtu => {
                                info.mtu = attr
                                    .get_payload_as::<u32>()
                                    .ok()
                                    .and_then(|mtu| Mtu::try_from(mtu).ok());
                            }
                            Ifla::Linkinfo => {
                                info.can = InterfaceCanParams::try_from(attr)?;
                            }
                            _ => (),
                        }
                    }
                }

                Ok(info)
            }
            None => Err(RouterError::NoAck),
        }
    }

    /// Set the MTU of this interface.
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    pub fn set_mtu(&self, mtu: Mtu) -> NlResult<()> {
        let mtu = mtu as u32;
        let info = self.info_msg({
            let mut buffer = RtBuffer::new();
            buffer.push(
                RtattrBuilder::default()
                    .rta_type(Ifla::Mtu)
                    .rta_payload(&mtu.to_ne_bytes()[..])
                    .build()?,
            );
            buffer
        })?;
        Self::send_info_msg(Rtm::Newlink, info, NlmF::empty())
    }

    /// Set a CAN-specific parameter.
    ///
    /// This send a netlink message down to the kernel to set an attribute
    /// in the link info, such as bitrate, control modes, etc
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    pub fn set_can_param<P>(&self, param_type: IflaCan, param: P) -> NlResult<()>
    where
        P: ToBytes + Size,
    {
        let info = self.info_msg({
            let data = RtattrBuilder::default()
                .rta_type(IflaInfo::Data)
                .rta_payload(Buffer::new())
                .build()?
                .nest(
                &RtattrBuilder::default()
                    .rta_type(param_type)
                    .rta_payload(param)
                    .build()?,
                ).map_err(|err| RouterError::Socket(SocketError::Ser(err)))?;

            let link_info = RtattrBuilder::default()
                .rta_type(Ifla::Linkinfo)
                .rta_payload(Buffer::new())
                .build()?
                .nest(
                &RtattrBuilder::default()
                    .rta_type(IflaInfo::Kind)
                    .rta_payload("can")
                    .build()?,
                ).map_err(|err| RouterError::Socket(SocketError::Ser(err)))?
                .nest(&data).map_err(|err| RouterError::Socket(SocketError::Ser(err)))?;

            let mut rtattrs = RtBuffer::new();
            rtattrs.push(link_info);
            rtattrs
        })?;
        Self::send_info_msg(Rtm::Newlink, info, NlmF::empty())
    }

    /// Set a CAN-specific set of parameters.
    ///
    /// This sends a netlink message down to the kernel to set multiple
    /// attributes in the link info, such as bitrate, control modes, etc.
    ///
    /// If you have many attributes to set this is preferred to calling
    /// [set_can_params][CanInterface::set_can_param] multiple times, since this only sends a
    /// single netlink message. Also some CAN drivers might only accept
    /// a set of attributes, not over multiple messages.
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    pub fn set_can_params(&self, params: &InterfaceCanParams) -> NlResult<()> {
        let info = self.info_msg(
            //RtBuffer<Ifla, Buffer>::try_from(params)?);
            RtBuffer::try_from(params)?,
        )?;
        /*
            let mut rtattrs: RtBuffer<Ifla, Buffer> = RtBuffer::new();
            let mut data = Rtattr::new(None, IflaInfo::Data, Buffer::new())?;

            if let Some(bt) = params.bit_timing {
                data.add_nested_attribute(&Rtattr::new(None, IflaCan::BitTiming, bt)?)?;
            }
            if let Some(r) = params.restart_ms {
                data.add_nested_attribute(&Rtattr::new(
                    None,
                    IflaCan::RestartMs,
                    &r.to_ne_bytes()[..],
                )?)?;
            }
            if let Some(cm) = params.ctrl_mode {
                data.add_nested_attribute(&Rtattr::new::<can_ctrlmode>(
                    None,
                    IflaCan::CtrlMode,
                    cm.into(),
                )?)?;
            }
            if let Some(dbt) = params.data_bit_timing {
                data.add_nested_attribute(&Rtattr::new(None, IflaCan::DataBitTiming, dbt)?)?;
            }
            if let Some(t) = params.termination {
                data.add_nested_attribute(&Rtattr::new(None, IflaCan::Termination, t)?)?;
            }

            let mut link_info = Rtattr::new(None, Ifla::Linkinfo, Buffer::new())?;
            link_info.add_nested_attribute(&Rtattr::new(None, IflaInfo::Kind, "can")?)?;
            link_info.add_nested_attribute(&data)?;

            rtattrs.push(link_info);
            rtattrs
        });
        */
        Self::send_info_msg(Rtm::Newlink, info, NlmF::empty())
    }

    /// Attempt to query an individual CAN parameter on the interface.
    pub fn can_param<P>(&self, param: IflaCan) -> NlResult<Option<P>>
    where
        P: FromBytes + Clone,
    {
        if let Some(hdr) = self.query_details()? {
            if let Some(payload) = hdr.get_payload() {
                for top_attr in payload.rtattrs().iter() {
                    if *top_attr.rta_type() == Ifla::Linkinfo {
                        for info in top_attr.get_attr_handle::<IflaInfo>()?.get_attrs() {
                            if *info.rta_type() == IflaInfo::Data {
                                for attr in info.get_attr_handle::<IflaCan>()?.get_attrs() {
                                    if *attr.rta_type() == param {
                                        return Ok(Some(attr.get_payload_as::<P>()?));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(None)
        } else {
            Err(RouterError::NoAck)
        }
    }

    /// Gets the current bit rate for the interface.
    pub fn bit_rate(&self) -> NlResult<Option<u32>> {
        Ok(self.bit_timing()?.map(|timing| timing.bitrate))
    }

    /// Set the bitrate and, optionally, sample point of this interface.
    ///
    /// The bitrate can *not* be changed if the interface is UP. It is
    /// specified in Hz (bps) while the sample point is given in tenths
    /// of a percent/
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    pub fn set_bitrate<P>(&self, bitrate: u32, sample_point: P) -> NlResult<()>
    where
        P: Into<Option<u32>>,
    {
        let sample_point: u32 = sample_point.into().unwrap_or(0);

        debug_assert!(
            0 < bitrate && bitrate <= 1000000,
            "Bitrate must be within 1..=1000000, received {}.",
            bitrate
        );
        debug_assert!(
            sample_point < 1000,
            "Sample point must be within 0..1000, received {}.",
            sample_point
        );

        self.set_bit_timing(CanBitTiming {
            bitrate,
            sample_point,
            ..CanBitTiming::default()
        })
    }

    /// Gets the bit timing params for the interface
    pub fn bit_timing(&self) -> NlResult<Option<CanBitTiming>> {
        self.can_param::<CanBitTiming>(IflaCan::BitTiming)
    }

    /// Sets the bit timing params for the interface
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    pub fn set_bit_timing(&self, timing: CanBitTiming) -> NlResult<()> {
        self.set_can_param(IflaCan::BitTiming, timing)
    }

    /// Gets the bit timing const data for the interface
    pub fn bit_timing_const(&self) -> NlResult<Option<CanBitTimingConst>> {
        self.can_param::<CanBitTimingConst>(IflaCan::BitTimingConst)
    }

    /// Gets the clock frequency for the interface
    pub fn clock(&self) -> NlResult<Option<u32>> {
        Ok(self
            .can_param::<CanClock>(IflaCan::Clock)?
            .map(|clk| clk.freq))
    }

    /// Gets the state of the interface
    pub fn state(&self) -> NlResult<Option<CanState>> {
        Ok(self
            .can_param::<u32>(IflaCan::State)?
            .and_then(|st| CanState::try_from(st).ok()))
    }

    /// Set the full control mode (bit) collection.
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    #[deprecated(since = "3.2.0", note = "Use `set_ctrlmodes` instead")]
    pub fn set_full_ctrlmode(&self, ctrlmode: can_ctrlmode) -> NlResult<()> {
        self.set_can_param(IflaCan::CtrlMode, ctrlmode)
    }

    /// Set the full control mode (bit) collection.
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    pub fn set_ctrlmodes<M>(&self, ctrlmode: M) -> NlResult<()>
    where
        M: Into<CanCtrlModes>,
    {
        let modes = ctrlmode.into();
        let modes: can_ctrlmode = modes.into();
        self.set_can_param(IflaCan::CtrlMode, modes)
    }

    /// Set or clear an individual control mode parameter.
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    pub fn set_ctrlmode(&self, mode: CanCtrlMode, on: bool) -> NlResult<()> {
        self.set_ctrlmodes(CanCtrlModes::from_mode(mode, on))
    }

    /// Gets the automatic CANbus restart time for the interface, in milliseconds.
    pub fn restart_ms(&self) -> NlResult<Option<u32>> {
        self.can_param::<u32>(IflaCan::RestartMs)
    }

    /// Set the automatic restart milliseconds of the interface
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    pub fn set_restart_ms(&self, restart_ms: u32) -> NlResult<()> {
        self.set_can_param(IflaCan::RestartMs, &restart_ms.to_ne_bytes()[..])
    }

    /// Manually restart the interface.
    ///
    /// Note that a manual restart if only permitted if automatic restart is
    /// disabled and the device is in the bus-off state.
    /// See: linux/drivers/net/can/dev/dev.c
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    /// Common Errors:
    ///     EINVAL - The interface is down or automatic restarts are enabled
    ///     EBUSY - The interface is not in a bus-off state
    ///
    pub fn restart(&self) -> NlResult<()> {
        // Note: The linux code shows the data type to be u32, but never
        // appears to access the value sent. iproute2 sends a 1, so we do
        // too!
        // See: linux/drivers/net/can/dev/netlink.c
        let restart_data: u32 = 1;
        self.set_can_param(IflaCan::Restart, &restart_data.to_ne_bytes()[..])
    }

    /// Gets the bus error counter from the interface
    pub fn berr_counter(&self) -> NlResult<Option<CanBerrCounter>> {
        self.can_param::<CanBerrCounter>(IflaCan::BerrCounter)
    }

    /// Gets the data bit timing params for the interface
    pub fn data_bit_timing(&self) -> NlResult<Option<CanBitTiming>> {
        self.can_param::<CanBitTiming>(IflaCan::DataBitTiming)
    }

    /// Sets the data bit timing params for the interface
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    pub fn set_data_bit_timing(&self, timing: CanBitTiming) -> NlResult<()> {
        self.set_can_param(IflaCan::DataBitTiming, timing)
    }

    /// Set the data bitrate and, optionally, data sample point of this
    /// interface.
    ///
    /// This only applies to interfaces in FD mode.
    ///
    /// The data bitrate can *not* be changed if the interface is UP. It is
    /// specified in Hz (bps) while the sample point is given in tenths
    /// of a percent/
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    pub fn set_data_bitrate<P>(&self, bitrate: u32, sample_point: P) -> NlResult<()>
    where
        P: Into<Option<u32>>,
    {
        let sample_point: u32 = sample_point.into().unwrap_or(0);

        self.set_data_bit_timing(CanBitTiming {
            bitrate,
            sample_point,
            ..CanBitTiming::default()
        })
    }

    /// Gets the data bit timing const params for the interface
    pub fn data_bit_timing_const(&self) -> NlResult<Option<CanBitTimingConst>> {
        self.can_param::<CanBitTimingConst>(IflaCan::DataBitTimingConst)
    }

    /// Sets the CANbus termination for the interface
    ///
    /// Not all interfaces support setting a termination.
    /// Termination is in ohms. Your interface most likely only supports
    /// certain values. Common values are 0 and 120.
    ///
    /// PRIVILEGED: This requires root privilege.
    ///
    pub fn set_termination(&self, termination: u16) -> NlResult<()> {
        self.set_can_param(IflaCan::Termination, termination)
    }

    /// Gets the CANbus termination for the interface
    pub fn termination(&self) -> NlResult<Option<u16>> {
        self.can_param::<u16>(IflaCan::Termination)
    }
}

/////////////////////////////////////////////////////////////////////////////

/// Netlink tests for SocketCAN control
#[cfg(feature = "netlink_tests")]
#[cfg(test)]
pub mod tests {
    use super::*;
    use serial_test::serial;
    use std::ops::Deref;

    /// RAII-style helper to create and clean-up a specific vcan interface for a single test.
    /// Using drop here ensures that the interface always gets cleaned up
    /// (although a restart would also remove it).
    ///
    /// Intended for use (ONLY) in tests as follows:
    /// ```
    /// #[test]
    /// fn my_test() {
    ///     let interface = TemporaryInterface::new("my_test").unwrap();
    ///     // use the interface..
    /// }
    /// ```
    /// Please note that there is a limit to the length of interface names,
    /// namely 16 characters on Linux.
    #[allow(missing_copy_implementations)]
    #[derive(Debug)]
    pub struct TemporaryInterface {
        interface: CanInterface,
    }

    impl TemporaryInterface {
        /// Creates a temporaty interface
        #[allow(unused)]
        pub fn new(name: &str) -> NlResult<Self> {
            Ok(Self {
                interface: CanInterface::create_vcan(name, None)?,
            })
        }
    }

    impl Drop for TemporaryInterface {
        fn drop(&mut self) {
            assert!(CanInterface::open_iface(self.interface.if_index)
                .delete()
                .is_ok());
        }
    }

    impl Deref for TemporaryInterface {
        type Target = CanInterface;

        fn deref(&self) -> &Self::Target {
            &self.interface
        }
    }

    #[test]
    #[serial]
    fn up_down() {
        let interface = TemporaryInterface::new("up_down").unwrap();

        assert!(interface.bring_up().is_ok());
        assert!(interface.details().unwrap().is_up);

        assert!(interface.bring_down().is_ok());
        assert!(!interface.details().unwrap().is_up);
    }

    #[test]
    #[serial]
    fn details() {
        let interface = TemporaryInterface::new("info").unwrap();
        let details = interface.details().unwrap();
        assert_eq!("info", details.name.unwrap());
        assert!(details.mtu.is_some());
        assert!(!details.is_up);
    }

    #[test]
    #[serial]
    fn mtu() {
        let interface = TemporaryInterface::new("mtu").unwrap();

        assert!(interface.set_mtu(Mtu::Fd).is_ok());
        assert_eq!(Mtu::Fd, interface.details().unwrap().mtu.unwrap());

        assert!(interface.set_mtu(Mtu::Standard).is_ok());
        assert_eq!(Mtu::Standard, interface.details().unwrap().mtu.unwrap());
    }
}
