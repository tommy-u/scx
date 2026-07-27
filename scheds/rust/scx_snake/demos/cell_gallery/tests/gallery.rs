// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet};

use scx_snake_cell_gallery::{
    build_gallery, render_policy, validate_canvas_affinity, validate_canvas_cpus, Playback,
    CANVAS_CPUS, MAX_CELLS,
};

#[test]
fn gallery_has_four_bounded_symmetric_images() {
    let gallery = build_gallery().expect("gallery should compile");
    let expected = BTreeMap::from([
        ("flower", (80_usize, 200_usize)),
        ("heart", (60, 140)),
        ("cat", (120, 300)),
        ("snake", (350, 450)),
    ]);

    assert_eq!(
        gallery
            .images
            .iter()
            .map(|image| image.name.as_str())
            .collect::<Vec<_>>(),
        vec!["flower", "heart", "cat", "snake"]
    );
    assert!(gallery.cells.len() <= MAX_CELLS);

    for image in &gallery.images {
        let (minimum, maximum) = expected[image.name.as_str()];
        assert!(
            (minimum..=maximum).contains(&image.cell_ids.len()),
            "{} uses {} cells, expected {minimum}..={maximum}",
            image.name,
            image.cell_ids.len()
        );

        let mut pixels = BTreeSet::new();
        for &cell_id in &image.cell_ids {
            let cell = &gallery.cells[cell_id as usize];
            let [from, to] = cell.cpus;
            pixels.insert((from, to));
            pixels.insert((to, from));
        }
        assert!(pixels.iter().all(|(row, column)| row != column));
        assert!(pixels
            .iter()
            .all(|(row, column)| pixels.contains(&(*column, *row))));
    }
}

#[test]
fn snake_has_a_wide_hood_narrow_neck_and_broad_coil() {
    let gallery = build_gallery().expect("gallery should compile");
    let snake = gallery
        .images
        .iter()
        .find(|image| image.name == "snake")
        .expect("snake image should exist");
    let center_sum = f64::from(CANVAS_CPUS - 1);
    let points = snake
        .cell_ids
        .iter()
        .flat_map(|&cell_id| {
            let [first, second] = gallery.cells[cell_id as usize].cpus;
            [(first, second), (second, first)]
        })
        .map(|(row, column)| {
            let row = f64::from(row);
            let column = f64::from(column);
            (
                (row - column) / std::f64::consts::SQRT_2,
                (row + column - center_sum) / std::f64::consts::SQRT_2,
            )
        })
        .collect::<Vec<_>>();
    let width_near = |target_y: f64| {
        let xs = points
            .iter()
            .filter(|(_, y)| (y - target_y).abs() <= 2.0)
            .map(|(x, _)| *x)
            .collect::<Vec<_>>();
        xs.iter().copied().fold(f64::NEG_INFINITY, f64::max)
            - xs.iter().copied().fold(f64::INFINITY, f64::min)
    };

    assert!(width_near(-25.0) >= 60.0, "cobra hood is too narrow");
    assert!(width_near(20.0) <= 34.0, "cobra neck is too wide");
    assert!(width_near(43.0) >= 70.0, "cobra coil is too narrow");
}

#[test]
fn gallery_cells_are_unique_valid_pairs_with_stable_ids() {
    let gallery = build_gallery().expect("gallery should compile");
    let mut pairs = BTreeSet::new();

    for (index, cell) in gallery.cells.iter().enumerate() {
        assert_eq!(cell.id as usize, index);
        assert!(cell.cpus[0] < cell.cpus[1]);
        assert!(cell.cpus[1] < CANVAS_CPUS);
        assert!(cell.image_mask != 0);
        assert!(pairs.insert(cell.cpus));
    }
}

#[test]
fn gallery_image_pixel_signatures_are_stable() {
    let gallery = build_gallery().expect("gallery should compile");
    let signatures = gallery
        .images
        .iter()
        .map(|image| {
            image
                .cell_ids
                .iter()
                .fold(0xcbf29ce484222325_u64, |hash, &id| {
                    gallery.cells[id as usize]
                        .cpus
                        .iter()
                        .flat_map(|cpu| cpu.to_le_bytes())
                        .fold(hash, |hash, byte| {
                            (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
                        })
                })
        })
        .collect::<Vec<_>>();

    assert_eq!(
        signatures,
        vec![
            2_211_987_663_553_981_803,
            6_777_740_739_144_757_994,
            16_609_405_729_104_203_065,
            7_904_809_648_054_255_193,
        ]
    );
}

#[test]
fn generated_policy_defines_every_cell_and_one_random_cell_rung() {
    let gallery = build_gallery().expect("gallery should compile");
    let policy = render_policy(&gallery);

    assert_eq!(policy.matches("[[cell]]").count(), gallery.cells.len());
    assert_eq!(policy.matches("[[rung]]").count(), 1);
    assert!(policy.starts_with("fallback = \"previous_cpu\"\n"));
    assert!(policy.contains("operation = \"pick_random_idle\""));
    assert!(policy.contains("scope = \"task_cell\""));
}

#[test]
fn image_membership_masks_exactly_match_worker_cohorts() {
    let gallery = build_gallery().expect("gallery should compile");

    for (image_index, image) in gallery.images.iter().enumerate() {
        let expected = gallery
            .cells
            .iter()
            .filter(|cell| cell.image_mask & (1_u8 << image_index) != 0)
            .map(|cell| cell.id)
            .collect::<Vec<_>>();
        assert_eq!(image.cell_ids, expected);
    }
}

#[test]
fn canvas_requires_exactly_numeric_cpus_zero_through_315() {
    let exact = (0..CANVAS_CPUS).collect::<Vec<_>>();
    validate_canvas_cpus(&exact).expect("exact canvas should be accepted");

    let missing = (0..CANVAS_CPUS - 1).collect::<Vec<_>>();
    assert!(validate_canvas_cpus(&missing)
        .expect_err("missing CPU should fail")
        .to_string()
        .contains("exactly 316"));

    let mut displaced = exact;
    displaced[315] = 316;
    assert!(validate_canvas_cpus(&displaced)
        .expect_err("non-numeric canvas should fail")
        .to_string()
        .contains("0 through 315"));
}

#[test]
fn canvas_affinity_must_include_every_gallery_cpu() {
    let exact = (0..CANVAS_CPUS).collect::<Vec<_>>();
    validate_canvas_affinity(&exact).expect("full canvas affinity should be accepted");

    let missing = (1..CANVAS_CPUS).collect::<Vec<_>>();
    assert!(validate_canvas_affinity(&missing)
        .expect_err("restricted affinity should fail")
        .to_string()
        .contains("CPU 0"));

    let mut with_extra = exact;
    with_extra.push(CANVAS_CPUS);
    validate_canvas_affinity(&with_extra).expect("extra affinity CPUs should be harmless");
}

#[test]
fn finite_playback_visits_every_image_for_each_cycle() {
    let playback = Playback::new(4, 2).expect("playback should be valid");
    assert_eq!(playback.collect::<Vec<_>>(), vec![0, 1, 2, 3, 0, 1, 2, 3]);
    assert!(Playback::new(0, 1).is_err());
}

#[test]
fn cell_membership_selects_only_its_images() {
    let gallery = build_gallery().expect("gallery should compile");
    for (image_index, image) in gallery.images.iter().enumerate() {
        for cell in &gallery.cells {
            assert_eq!(
                cell.is_active_for(image_index),
                image.cell_ids.contains(&cell.id)
            );
        }
    }
}
