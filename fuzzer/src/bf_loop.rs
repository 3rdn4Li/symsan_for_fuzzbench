use crate::{branches::GlobalBranches, command::CommandOpt, depot::Depot, executor::Executor};
use std::sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex, RwLock};

use std::thread;

use crate::afl::*;
use crate::parser::*;
use crate::solution::Solution;
use crate::track_cons::*;
use crate::union_table::*;
use crate::bf_main::BF_NEWCOVERAGE;
use fastgen_common::config;
use nix::unistd::close;
use std::collections::HashMap;
use std::collections::HashSet;
use std::os::unix::io::RawFd;

pub fn dispatcher(
    table: &UnionTable,
    branch_gencount: Arc<RwLock<HashMap<(u64, u32, u32, u64), u32>>>,
    branch_fliplist: Arc<RwLock<HashSet<(u64, u32, u32, u64)>>>,
    branch_hitcount: Arc<RwLock<HashMap<(u64, u32, u32, u64), u32>>>,
    buf: &Vec<u8>,
    id: RawFd,
    bq: &mut Vec<Solution>,
) {
    //let (labels,mut memcmp_data) = read_pipe(id);
    let mut tb = SearchTaskBuilder::new(buf.len());
    scan_nested_tasks(
        id,
        table,
        config::MAX_INPUT_LEN,
        &branch_gencount,
        &branch_fliplist,
        &branch_hitcount,
        buf,
        &mut tb,
        bq,
    );
}

pub fn grading_loop(
    cmd_opt: CommandOpt,
    depot: Arc<Depot>,
    global_branches: Arc<GlobalBranches>,
    branch_gencount: Arc<RwLock<HashMap<(u64, u32, u32, u64), u32>>>,
    branch_fliplist: Arc<RwLock<HashSet<(u64, u32, u32, u64)>>>,
    forklock: Arc<Mutex<u32>>,
    bq: Vec<Solution>,
) {
    let mut executor = Executor::new(
        cmd_opt,
        global_branches,
        depot.clone(),
        0,
        true, //grading
        forklock.clone(),
    );

    let mut sol_conds = 0;
    let mut flipped = 0;
    let mut not_reached = 0;
    let mut reached = 0;

    for sol in &bq {
        if let Some(buf) = depot.get_input_buf(sol.fid as usize) {
            let mut_buf = mutate(buf, &sol.sol, sol.field_index, sol.field_size);
            let new_path = executor.run_sync(&mut_buf);
            if new_path.0 {
                BF_NEWCOVERAGE.store(true, Ordering::SeqCst);
                info!(
                    "grading input derived from on input {} by  \
                flipping branch@ {:#01x} ctx {:#01x} order {}, \
                it is a new input {}, saved as input #{}",
                    sol.fid, sol.addr, sol.ctx, sol.order, new_path.0, new_path.1
                );
                let mut count = 1;
                if sol.addr != 0
                    && branch_gencount.read().unwrap().contains_key(&(
                        sol.addr,
                        sol.ctx,
                        sol.order,
                        sol.direction,
                    ))
                {
                    count = *branch_gencount
                        .read()
                        .unwrap()
                        .get(&(sol.addr, sol.ctx, sol.order, sol.direction))
                        .unwrap();
                    count += 1;
                    //info!("gencount is {}",count);
                }
                branch_gencount
                    .write()
                    .unwrap()
                    .insert((sol.addr, sol.ctx, sol.order, sol.direction), count);
                //info!("next input addr is {:} ctx is {}",addr,ctx);
            }
        }
    }
}

pub fn fuzz_loop(
    cmd_opt: CommandOpt,
    depot: Arc<Depot>,
    global_branches: Arc<GlobalBranches>,
    branch_gencount: Arc<RwLock<HashMap<(u64, u32, u32, u64), u32>>>,
    branch_fliplist: Arc<RwLock<HashSet<(u64, u32, u32, u64)>>>,
    restart: bool,
    forklock: Arc<Mutex<u32>>,
    id: u32,
) -> Vec<Solution> {
    let solutions = Vec::new();
    if (id as usize) >= depot.get_num_inputs() {
        return solutions;
    }

    let shmid = unsafe {
        libc::shmget(
            libc::IPC_PRIVATE,
            0xc00000000,
            0o644 | libc::IPC_CREAT | libc::SHM_NORESERVE,
        )
    };

    info!("start fuzz loop with shmid {}", shmid);

    let mut executor = Executor::new(
        cmd_opt,
        global_branches,
        depot.clone(),
        shmid,
        true, //not grading
        forklock.clone(),
    );

    let ptr = unsafe { libc::shmat(shmid, std::ptr::null(), 0) as *mut UnionTable };
    let table = unsafe { &*ptr };
    let branch_hitcount = Arc::new(RwLock::new(HashMap::<(u64, u32, u32, u64), u32>::new()));

    if let Some(buf) = depot.get_input_buf(id as usize) {
        let buf_cloned = buf.clone();
        //let path = depot.get_input_path(id).to_str().unwrap().to_owned();
        let gbranch_hitcount = branch_hitcount.clone();
        let gbranch_fliplist = branch_fliplist.clone();
        let gbranch_gencount = branch_gencount.clone();
        let mut solution_queue = Vec::new();

        let (mut child, read_end) = executor.track(id as usize, &buf);

        dispatcher(
            table,
            gbranch_gencount,
            gbranch_fliplist,
            gbranch_hitcount,
            &buf_cloned,
            read_end,
            &mut solution_queue,
        );

        //dispatcher(table, gbranch_gencount, gbranch_hitcount, &buf_cloned, read_end);
        close(read_end)
            .map_err(|err| warn!("close read end {:?}", err))
            .ok();

        //let timeout = time::Duration::from_secs(10);
        match child.try_wait() {
            //match child.wait_timeout(timeout) {
            Ok(Some(status)) => println!("exited with: {}", status),
            Ok(None) => {
                warn!("status not ready yet, let's really wait");
                child.kill();
                let res = child.wait();
                println!("result: {:?}", res);
            }
            Err(e) => println!("error attempting to wait: {}", e),
        }
        return solution_queue;
    }

    return solutions;
}
