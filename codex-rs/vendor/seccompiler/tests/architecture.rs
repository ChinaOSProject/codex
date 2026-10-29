// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#![allow(clippy::undocumented_unsafe_blocks)]

use seccompiler::{
    apply_filter, sock_filter, BpfProgram, SeccompAction, SeccompFilter, TargetArch,
};
use std::collections::BTreeMap;
use std::env::consts::ARCH;

const ARCHITECTURES: [(TargetArch, u32); 4] = [
    (TargetArch::x86_64, 0xc000_003e),
    (TargetArch::aarch64, 0xc000_00b7),
    (TargetArch::riscv64, 0xc000_00f3),
    (TargetArch::loongarch64, 0xc000_0102),
];

#[test]
fn test_architecture_guard() {
    for (arch, audit_value) in ARCHITECTURES {
        let program: BpfProgram = SeccompFilter::new(
            BTreeMap::new(),
            SeccompAction::Allow,
            SeccompAction::Trap,
            arch,
        )
        .unwrap()
        .try_into()
        .unwrap();

        // Even an empty policy must kill on an architecture mismatch before allowing a syscall.
        let expected = [
            (0x20, 0, 0, 4),
            (0x15, 1, 0, audit_value),
            (0x06, 0, 0, 0x8000_0000),
            (0x06, 0, 0, 0x7fff_0000),
        ]
        .map(|(code, jt, jf, k)| sock_filter { code, jt, jf, k });
        assert_eq!(program, expected, "{arch:?}");
    }
}

fn run_in_child(program: &[sock_filter], check: fn() -> bool) -> i32 {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
    if pid == 0 {
        if apply_filter(program).is_err() {
            unsafe { libc::_exit(100) };
        }
        let succeeded = check();
        // Do not return to the test harness with a filter installed.
        unsafe { libc::_exit(if succeeded { 0 } else { 1 }) };
    }

    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    status
}

fn check_allowed_and_denied_syscalls() -> bool {
    // Use raw syscalls so libc caching or a vDSO cannot bypass the filter.
    let allowed_pid = unsafe { libc::syscall(libc::SYS_getpid) };
    let denied_pid = unsafe { libc::syscall(libc::SYS_getppid) };
    allowed_pid > 0
        && denied_pid == -1
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[test]
fn test_filter_actions_in_child_process() {
    for action in [
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::KillProcess,
    ] {
        let program: BpfProgram = SeccompFilter::new(
            [libc::SYS_getpid, libc::SYS_exit, libc::SYS_exit_group]
                .into_iter()
                .map(|nr| (nr, vec![]))
                .collect(),
            action.clone(),
            SeccompAction::Allow,
            ARCH.try_into().unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();

        let status = run_in_child(&program, check_allowed_and_denied_syscalls);
        if action == SeccompAction::KillProcess {
            assert!(libc::WIFSIGNALED(status));
            assert_eq!(libc::WTERMSIG(status), libc::SIGSYS);
        } else {
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }
}

#[test]
fn test_wrong_target_architectures() {
    let native = TargetArch::try_from(ARCH).unwrap();
    for (arch, _) in ARCHITECTURES {
        if arch == native {
            continue;
        }
        let program: BpfProgram = SeccompFilter::new(
            BTreeMap::new(),
            SeccompAction::Allow,
            SeccompAction::Trap,
            arch,
        )
        .unwrap()
        .try_into()
        .unwrap();

        let status = run_in_child(&program, || unsafe { libc::syscall(libc::SYS_getpid) > 0 });
        assert!(libc::WIFSIGNALED(status), "{arch:?}: {status}");
        assert_eq!(libc::WTERMSIG(status), libc::SIGSYS, "{arch:?}");
    }
}

#[cfg(feature = "json")]
#[test]
fn test_json_architectures() {
    let input = r#"{
        "main": {
            "mismatch_action": {"errno": 1},
            "match_action": "allow",
            "filter": [{"syscall": "getpid"}, {"syscall": "exit"}, {"syscall": "exit_group"}]
        }
    }"#;
    for (arch, getpid, exit, exit_group) in [
        (TargetArch::x86_64, 39, 60, 231),
        (TargetArch::aarch64, 172, 93, 94),
        (TargetArch::riscv64, 172, 93, 94),
        (TargetArch::loongarch64, 172, 93, 94),
    ] {
        let program: BpfProgram = SeccompFilter::new(
            [getpid, exit, exit_group]
                .into_iter()
                .map(|nr| (nr, vec![]))
                .collect(),
            SeccompAction::Errno(1),
            SeccompAction::Allow,
            arch,
        )
        .unwrap()
        .try_into()
        .unwrap();
        let mut programs = seccompiler::compile_from_json(input.as_bytes(), arch).unwrap();
        let json_program = programs.remove("main").unwrap();
        assert_eq!(json_program, program, "{arch:?}");

        if arch == TargetArch::try_from(ARCH).unwrap() {
            let status = run_in_child(&json_program, check_allowed_and_denied_syscalls);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }
}
