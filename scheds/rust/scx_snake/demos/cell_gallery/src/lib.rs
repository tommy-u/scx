// SPDX-License-Identifier: GPL-2.0-only

//! Static cell-art generation for the standalone Snake gallery demo.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::f64::consts::{PI, SQRT_2};
use std::fmt::{Display, Formatter, Write};

pub const CANVAS_CPUS: u32 = 316;
pub const MAX_CELLS: usize = 1024;

const CENTER: f64 = (CANVAS_CPUS as f64 - 1.0) / 2.0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GalleryCell {
    pub id: u32,
    pub cpus: [u32; 2],
    pub image_mask: u8,
}

impl GalleryCell {
    pub fn is_active_for(&self, image_index: usize) -> bool {
        image_index < u8::BITS as usize && self.image_mask & (1_u8 << image_index) != 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GalleryImage {
    pub name: String,
    pub cell_ids: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Gallery {
    pub cells: Vec<GalleryCell>,
    pub images: Vec<GalleryImage>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GalleryError(String);

impl GalleryError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl Display for GalleryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for GalleryError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Playback {
    image_count: usize,
    emitted: u64,
    total: Option<u64>,
}

impl Playback {
    pub fn new(image_count: usize, cycles: u32) -> Result<Self, GalleryError> {
        if image_count == 0 {
            return Err(GalleryError::new("playback requires at least one image"));
        }
        let total = if cycles == 0 {
            None
        } else {
            Some(
                u64::try_from(image_count)
                    .ok()
                    .and_then(|count| count.checked_mul(u64::from(cycles)))
                    .ok_or_else(|| GalleryError::new("playback length overflow"))?,
            )
        };
        Ok(Self {
            image_count,
            emitted: 0,
            total,
        })
    }
}

impl Iterator for Playback {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.total.is_some_and(|total| self.emitted >= total) {
            return None;
        }
        let index = self.emitted as usize % self.image_count;
        self.emitted = self.emitted.saturating_add(1);
        Some(index)
    }
}

type Pixel = (u32, u32);
type LocalPoint = (f64, f64);

pub fn build_gallery() -> Result<Gallery, GalleryError> {
    let shapes = [
        ("flower", flower()),
        ("heart", heart()),
        ("cat", cat()),
        ("snake", snake()),
    ];
    let mut memberships = BTreeMap::<[u32; 2], u8>::new();
    let mut image_pairs = Vec::with_capacity(shapes.len());

    for (image_index, (name, pixels)) in shapes.into_iter().enumerate() {
        let mut pairs = BTreeSet::new();
        for (row, column) in pixels {
            if row == column {
                continue;
            }
            let pair = if row < column {
                [row, column]
            } else {
                [column, row]
            };
            pairs.insert(pair);
            *memberships.entry(pair).or_default() |= 1_u8 << image_index;
        }
        if pairs.is_empty() {
            return Err(GalleryError::new(format!("image `{name}` is empty")));
        }
        image_pairs.push((name.to_owned(), pairs));
    }

    if memberships.len() > MAX_CELLS {
        return Err(GalleryError::new(format!(
            "gallery needs {} cells, maximum is {MAX_CELLS}",
            memberships.len()
        )));
    }

    let mut pair_ids = BTreeMap::new();
    let mut cells = Vec::with_capacity(memberships.len());
    for (index, (cpus, image_mask)) in memberships.into_iter().enumerate() {
        let id = u32::try_from(index)
            .map_err(|_| GalleryError::new("gallery cell ID does not fit u32"))?;
        pair_ids.insert(cpus, id);
        cells.push(GalleryCell {
            id,
            cpus,
            image_mask,
        });
    }

    let images = image_pairs
        .into_iter()
        .map(|(name, pairs)| GalleryImage {
            name,
            cell_ids: pairs
                .into_iter()
                .filter_map(|pair| pair_ids.get(&pair).copied())
                .collect(),
        })
        .collect();

    Ok(Gallery { cells, images })
}

pub fn render_policy(gallery: &Gallery) -> String {
    let mut output = String::from("fallback = \"previous_cpu\"\n");
    for cell in &gallery.cells {
        let _ = write!(
            output,
            "\n[[cell]]\nid = {}\ncpus = \"{},{}\"\n",
            cell.id, cell.cpus[0], cell.cpus[1]
        );
    }
    output.push_str("\n[[rung]]\noperation = \"pick_random_idle\"\nscope = \"task_cell\"\n");
    output
}

pub fn validate_canvas_cpus(cpus: &[u32]) -> Result<(), GalleryError> {
    if cpus.len() != CANVAS_CPUS as usize {
        return Err(GalleryError::new(format!(
            "cell-art gallery requires exactly {CANVAS_CPUS} online CPUs, found {}",
            cpus.len()
        )));
    }
    if cpus.iter().copied().ne(0..CANVAS_CPUS) {
        return Err(GalleryError::new(format!(
            "cell-art gallery requires numeric CPU IDs 0 through {}",
            CANVAS_CPUS - 1
        )));
    }
    Ok(())
}

pub fn validate_canvas_affinity(cpus: &[u32]) -> Result<(), GalleryError> {
    let allowed = cpus.iter().copied().collect::<BTreeSet<_>>();
    let missing = (0..CANVAS_CPUS)
        .filter(|cpu| !allowed.contains(cpu))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(GalleryError::new(format!(
            "cell-art gallery process affinity is missing CPU{} {}",
            if missing.len() == 1 { "" } else { "s" },
            missing
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )));
    }
    Ok(())
}

fn flower() -> BTreeSet<Pixel> {
    let mut canvas = Canvas::default();
    canvas.parametric(0.0, 2.0 * PI, 720, true, |angle| {
        let radius = 30.0 + 6.0 * (8.0 * angle).cos();
        (radius * angle.sin(), -radius * angle.cos())
    });
    canvas.ellipse((0.0, 0.0), (6.0, 6.0), 120);
    canvas.pixels
}

fn heart() -> BTreeSet<Pixel> {
    let mut canvas = Canvas::default();
    canvas.parametric(0.0, 2.0 * PI, 480, true, |angle| {
        let x = 2.55 * 16.0 * angle.sin().powi(3);
        let y = -2.55
            * (13.0 * angle.cos()
                - 5.0 * (2.0 * angle).cos()
                - 2.0 * (3.0 * angle).cos()
                - (4.0 * angle).cos());
        (x, y)
    });
    canvas.pixels
}

fn cat() -> BTreeSet<Pixel> {
    let mut canvas = Canvas::default();
    canvas.polyline(
        &[
            (-38.0, 17.0),
            (-42.0, -13.0),
            (-34.0, -33.0),
            (-29.0, -55.0),
            (-11.0, -43.0),
            (0.0, -46.0),
            (11.0, -43.0),
            (29.0, -55.0),
            (34.0, -33.0),
            (42.0, -13.0),
            (38.0, 17.0),
            (25.0, 38.0),
            (0.0, 47.0),
            (-25.0, 38.0),
        ],
        true,
    );
    canvas.ellipse((-16.0, -7.0), (7.0, 4.0), 64);
    canvas.ellipse((16.0, -7.0), (7.0, 4.0), 64);
    canvas.polyline(&[(0.0, 7.0), (5.0, 12.0), (0.0, 16.0), (-5.0, 12.0)], true);
    canvas.polyline(&[(0.0, 16.0), (-7.0, 23.0), (-15.0, 21.0)], false);
    canvas.polyline(&[(0.0, 16.0), (7.0, 23.0), (15.0, 21.0)], false);
    for (inner_y, outer_y) in [(12.0, 7.0), (18.0, 18.0), (24.0, 30.0)] {
        canvas.polyline(&[(-12.0, inner_y), (-43.0, outer_y)], false);
        canvas.polyline(&[(12.0, inner_y), (43.0, outer_y)], false);
    }
    canvas.pixels
}

fn snake() -> BTreeSet<Pixel> {
    let mut canvas = Canvas::default();
    canvas.polyline(
        &[
            (-8.0, -57.0),
            (-20.0, -52.0),
            (-31.0, -42.0),
            (-38.0, -27.0),
            (-37.0, -11.0),
            (-28.0, 2.0),
            (-17.0, 8.0),
            (-12.0, 22.0),
            (12.0, 22.0),
            (17.0, 8.0),
            (28.0, 2.0),
            (37.0, -11.0),
            (38.0, -27.0),
            (31.0, -42.0),
            (20.0, -52.0),
            (8.0, -57.0),
        ],
        true,
    );
    canvas.ellipse((0.0, -47.0), (14.0, 12.0), 120);
    canvas.ellipse((-5.5, -49.0), (2.5, 3.5), 40);
    canvas.ellipse((5.5, -49.0), (2.5, 3.5), 40);
    canvas.ellipse((-23.0, -22.0), (5.0, 9.0), 64);
    canvas.ellipse((23.0, -22.0), (5.0, 9.0), 64);
    canvas.polyline(&[(-6.0, -41.0), (0.0, -38.0), (6.0, -41.0)], false);
    canvas.polyline(&[(0.0, -38.0), (0.0, -29.0), (-5.0, -23.0)], false);
    canvas.polyline(&[(0.0, -29.0), (5.0, -23.0)], false);
    canvas.polyline(&[(-12.0, 18.0), (-10.0, 31.0), (-18.0, 37.0)], false);
    canvas.polyline(&[(12.0, 18.0), (10.0, 31.0), (18.0, 37.0)], false);
    canvas.ellipse((0.0, 43.0), (42.0, 16.0), 220);
    canvas.ellipse((0.0, 45.0), (24.0, 7.0), 120);
    canvas.pixels
}

#[derive(Default)]
struct Canvas {
    pixels: BTreeSet<Pixel>,
}

impl Canvas {
    fn ellipse(&mut self, center: LocalPoint, radii: LocalPoint, samples: usize) {
        self.parametric(0.0, 2.0 * PI, samples, true, |angle| {
            (
                center.0 + radii.0 * angle.cos(),
                center.1 + radii.1 * angle.sin(),
            )
        });
    }

    fn parametric<F>(&mut self, start: f64, end: f64, samples: usize, closed: bool, curve: F)
    where
        F: Fn(f64) -> LocalPoint,
    {
        let points = (0..=samples)
            .map(|index| {
                let fraction = index as f64 / samples as f64;
                curve(start + (end - start) * fraction)
            })
            .collect::<Vec<_>>();
        self.polyline(&points, closed);
    }

    fn polyline(&mut self, points: &[LocalPoint], closed: bool) {
        for pair in points.windows(2) {
            self.line(map_local(pair[0]), map_local(pair[1]));
        }
        if closed && points.len() > 2 {
            self.line(map_local(points[points.len() - 1]), map_local(points[0]));
        }
    }

    fn line(&mut self, start: (i32, i32), end: (i32, i32)) {
        let (mut row, mut column) = start;
        let row_step = if row < end.0 { 1 } else { -1 };
        let column_step = if column < end.1 { 1 } else { -1 };
        let delta_row = (end.0 - row).abs();
        let delta_column = -(end.1 - column).abs();
        let mut error = delta_row + delta_column;

        loop {
            if row >= 0 && column >= 0 && row < CANVAS_CPUS as i32 && column < CANVAS_CPUS as i32 {
                self.pixels.insert((row as u32, column as u32));
            }
            if (row, column) == end {
                break;
            }
            let doubled = 2 * error;
            if doubled >= delta_column {
                error += delta_column;
                row += row_step;
            }
            if doubled <= delta_row {
                error += delta_row;
                column += column_step;
            }
        }
    }
}

fn map_local((x, y): LocalPoint) -> (i32, i32) {
    (
        (CENTER + (y + x) / SQRT_2).round() as i32,
        (CENTER + (y - x) / SQRT_2).round() as i32,
    )
}
