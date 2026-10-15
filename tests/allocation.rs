use rewind::{
    decode,
    history::worker::Accounts,
    reconstruct::apply_write,
    types::{LOADER, LOADER_V4},
};
use solana_address::Address;
use solana_message::compiled_instruction::CompiledInstruction;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

struct CountingAllocator;
thread_local! { static ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) }; }
fn count() {
    let _ = ALLOCATIONS.try_with(|counter| {
        if let Some(value) = counter.get() {
            counter.set(Some(value + 1));
        }
    });
}
// SAFETY: every allocation is delegated unchanged to the system allocator; the
// thread-local counter stores only an integer and does not allocate recursively.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count();
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn borrowed_filter_decoder_and_write_loop_do_not_allocate() {
    let target = Address::new_from_array([4; 32]);
    let static_keys = [LOADER];
    let writable = [target];
    let readonly = [Address::new_from_array([8; 32])];
    let keys = Accounts {
        static_keys: &static_keys,
        writable: &writable,
        readonly: &readonly,
    };
    let instruction = CompiledInstruction {
        program_id_index: 0,
        accounts: vec![1, 2],
        data: vec![],
    };
    let mut wire = vec![];
    wire.extend(1u32.to_le_bytes());
    wire.extend(3u32.to_le_bytes());
    wire.extend(3u64.to_le_bytes());
    wire.extend([1, 2, 3]);
    let mut payload = [0; 16];
    let mut coverage = [0; 2];
    ALLOCATIONS.with(|counter| counter.set(Some(0)));
    for _ in 0..10000 {
        assert!(keys.candidate(&instruction, target, None).unwrap());
        if let decode::Loader::Write { offset, bytes } = decode::loader(&wire).unwrap() {
            apply_write(&mut payload, &mut coverage, offset, bytes).unwrap();
        } else {
            panic!("not a write");
        }
    }
    let allocations = ALLOCATIONS.with(|counter| counter.replace(None).unwrap());
    assert_eq!(allocations, 0);
    assert_eq!(&payload[3..6], &[1, 2, 3]);
}

#[test]
fn v4_filter_and_borrowed_borsh_decoder_do_not_allocate() {
    let target = Address::new_from_array([4; 32]);
    let static_keys = [LOADER_V4, target];
    let keys = Accounts {
        static_keys: &static_keys,
        writable: &[],
        readonly: &[],
    };
    let instruction = CompiledInstruction {
        program_id_index: 0,
        accounts: vec![1],
        data: vec![],
    };
    let mut wire = vec![0];
    wire.extend(3u32.to_le_bytes());
    wire.extend(3u32.to_le_bytes());
    wire.extend([1, 2, 3]);
    let mut payload = [0; 16];
    let mut coverage = [0; 2];
    ALLOCATIONS.with(|counter| counter.set(Some(0)));
    for _ in 0..10000 {
        assert!(keys.candidate(&instruction, target, None).unwrap());
        if let decode::V4::Write { offset, bytes } = decode::v4(&wire).unwrap() {
            apply_write(&mut payload, &mut coverage, offset, bytes).unwrap();
        } else {
            panic!("not a write");
        }
    }
    let allocations = ALLOCATIONS.with(|counter| counter.replace(None).unwrap());
    assert_eq!(allocations, 0);
    assert_eq!(&payload[3..6], &[1, 2, 3]);
}
