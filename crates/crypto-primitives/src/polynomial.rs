use curve25519_dalek::scalar::Scalar;

/// Evaluate at 1, ..., count using finite differences after the first degree+1
/// evaluations. Consecutive committee coordinates let the remaining points use
/// only additions. The loop bounds depend only on public dimensions.
pub fn evaluate_consecutive(coefficients: &[Scalar], count: usize) -> Vec<Scalar> {
    let initial = coefficients.len().min(count);
    if initial == 0 {
        return vec![Scalar::ZERO; count];
    }
    let mut values = (1..=initial)
        .map(|x| evaluate(coefficients, Scalar::from(x as u64)))
        .collect::<Vec<_>>();
    if initial == count {
        return values;
    }
    let mut differences = values.clone();
    let mut last = vec![*differences.last().expect("nonempty")];
    while differences.len() > 1 {
        for i in 0..differences.len() - 1 {
            differences[i] = differences[i + 1] - differences[i];
        }
        differences.pop();
        last.push(*differences.last().expect("nonempty"));
    }
    while values.len() < count {
        for order in (0..last.len() - 1).rev() {
            last[order] = last[order] + last[order + 1];
        }
        values.push(last[0]);
    }
    values
}
use rand::RngCore;
use std::ops::AddAssign;
use thiserror::Error;

pub fn random_scalar<R: RngCore + ?Sized>(rng: &mut R) -> Scalar {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

pub fn sample_polynomial<R: RngCore + ?Sized>(
    secret: Scalar,
    coefficient_count: usize,
    rng: &mut R,
) -> Result<Vec<Scalar>, PolynomialError> {
    if coefficient_count == 0 {
        return Err(PolynomialError::InvalidCoefficientCount);
    }
    let mut coefficients = Vec::with_capacity(coefficient_count);
    coefficients.push(secret);
    for _ in 1..coefficient_count {
        coefficients.push(random_scalar(rng));
    }
    Ok(coefficients)
}

pub fn sample_random_polynomial<R: RngCore + ?Sized>(
    coefficient_count: usize,
    rng: &mut R,
) -> Result<Vec<Scalar>, PolynomialError> {
    if coefficient_count == 0 {
        return Err(PolynomialError::InvalidCoefficientCount);
    }
    Ok((0..coefficient_count).map(|_| random_scalar(rng)).collect())
}

pub fn evaluate(coefficients: &[Scalar], point: Scalar) -> Scalar {
    let Some((leading, remaining)) = coefficients.split_last() else {
        return Scalar::ZERO;
    };
    remaining
        .iter()
        .rev()
        .fold(*leading, |acc, coefficient| acc * point + coefficient)
}

pub fn powers(point: Scalar, len: usize) -> Vec<Scalar> {
    let mut result = Vec::with_capacity(len);
    let mut current = Scalar::ONE;
    for _ in 0..len {
        result.push(current);
        current *= point;
    }
    result
}

pub fn add(left: &[Scalar], right: &[Scalar], right_scale: Scalar) -> Vec<Scalar> {
    let len = left.len().max(right.len());
    (0..len)
        .map(|index| {
            left.get(index).copied().unwrap_or(Scalar::ZERO)
                + right_scale * right.get(index).copied().unwrap_or(Scalar::ZERO)
        })
        .collect()
}

pub fn interpolate_at_zero(
    shares: &[(Scalar, Scalar)],
    threshold: usize,
) -> Result<Scalar, PolynomialError> {
    if threshold == 0 {
        return Err(PolynomialError::InvalidCoefficientCount);
    }
    if shares.len() != threshold {
        return Err(PolynomialError::WrongShareCount {
            have: shares.len(),
            need: threshold,
        });
    }
    if shares.iter().any(|(point, _)| *point == Scalar::ZERO) {
        return Err(PolynomialError::ZeroEvaluationPoint);
    }
    let mut result = Scalar::ZERO;
    for (i, (x_i, y_i)) in shares.iter().copied().enumerate() {
        let mut basis = Scalar::ONE;
        for (j, (x_j, _)) in shares.iter().copied().enumerate() {
            if i == j {
                continue;
            }
            let denominator = x_i - x_j;
            if denominator == Scalar::ZERO {
                return Err(PolynomialError::DuplicatePoint);
            }
            basis *= -x_j * denominator.invert();
        }
        result += y_i * basis;
    }
    Ok(result)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolynomialOpCounts {
    pub scalar_additions: u64,
    pub scalar_multiplications: u64,
    pub schoolbook_calls: u64,
    pub karatsuba_calls: u64,
    pub division_calls: u64,
    pub batch_inversions: u64,
}

impl AddAssign for PolynomialOpCounts {
    fn add_assign(&mut self, other: Self) {
        self.scalar_additions += other.scalar_additions;
        self.scalar_multiplications += other.scalar_multiplications;
        self.schoolbook_calls += other.schoolbook_calls;
        self.karatsuba_calls += other.karatsuba_calls;
        self.division_calls += other.division_calls;
        self.batch_inversions += other.batch_inversions;
    }
}

/// Reusable adaptive evaluation plan for an ordered set of points.
///
/// Reconstruction commonly evaluates many dealer polynomials at the same
/// sender coordinates. Small sets use a low-constant direct pass. Larger sets
/// reuse a product/remainder tree and its planned divisor reciprocals.
#[derive(Clone, Debug)]
pub struct MultipointEvaluationPlan {
    points: Vec<Scalar>,
    tree: ProductNode,
}

// The response polynomials used by the measured committees are short.  At
// these sizes a counted Horner pass has substantially lower constants than a
// recursive remainder tree, even when the tree itself is reused.  Larger
// point sets retain the subquadratic path below.
const DIRECT_MULTIPOINT_MAX_POINTS: usize = 64;

impl MultipointEvaluationPlan {
    pub fn new(points: &[Scalar]) -> Result<(Self, PolynomialOpCounts), PolynomialError> {
        if points.is_empty() {
            return Err(PolynomialError::InvalidCoefficientCount);
        }
        let mut unique = points.to_vec();
        unique.sort_by_key(Scalar::to_bytes);
        unique.dedup();
        if unique.len() != points.len() {
            return Err(PolynomialError::DuplicatePoint);
        }
        let mut counts = PolynomialOpCounts::default();
        let mut tree = ProductNode::build(points, &mut counts);
        tree.prepare_remainder_plans(&mut counts)?;
        Ok((
            Self {
                points: points.to_vec(),
                tree,
            },
            counts,
        ))
    }

    pub fn points(&self) -> &[Scalar] {
        &self.points
    }

    pub fn evaluate(
        &self,
        polynomial: &[Scalar],
    ) -> Result<(Vec<Scalar>, PolynomialOpCounts), PolynomialError> {
        if polynomial.is_empty() {
            return Err(PolynomialError::InvalidCoefficientCount);
        }
        if self.points.len() <= DIRECT_MULTIPOINT_MAX_POINTS
            && polynomial.len() <= DIRECT_MULTIPOINT_MAX_POINTS
        {
            let mut counts = PolynomialOpCounts::default();
            let values = self
                .points
                .iter()
                .map(|point| evaluate_counted(polynomial, *point, &mut counts))
                .collect();
            return Ok((values, counts));
        }
        let mut counts = PolynomialOpCounts::default();
        let root_remainder = polynomial_remainder(polynomial, &self.tree.polynomial, &mut counts)?;
        let mut values = vec![Scalar::ZERO; self.points.len()];
        self.tree
            .evaluate_remainder(&root_remainder, &mut values, &mut counts)?;
        Ok((values, counts))
    }

    pub fn interpolation_weights_at_zero(
        &self,
    ) -> Result<(Vec<Scalar>, PolynomialOpCounts), PolynomialError> {
        if self.points.contains(&Scalar::ZERO) {
            return Err(PolynomialError::ZeroEvaluationPoint);
        }
        let mut counts = PolynomialOpCounts::default();
        let derivative = derivative(&self.tree.polynomial, &mut counts);
        let root_remainder = polynomial_remainder(&derivative, &self.tree.polynomial, &mut counts)?;
        let mut derivative_values = vec![Scalar::ZERO; self.points.len()];
        self.tree
            .evaluate_remainder(&root_remainder, &mut derivative_values, &mut counts)?;
        let denominators = self
            .points
            .iter()
            .zip(&derivative_values)
            .map(|(point, value)| -*point * *value)
            .collect::<Vec<_>>();
        counts.scalar_multiplications += denominators.len() as u64;
        let inverses = batch_invert(&denominators, &mut counts)?;
        let p_zero = self.tree.polynomial[0];
        let weights = inverses
            .into_iter()
            .map(|inverse| p_zero * inverse)
            .collect::<Vec<_>>();
        counts.scalar_multiplications += weights.len() as u64;
        Ok((weights, counts))
    }
}

/// Multiplies polynomials with a Karatsuba recursion above a small base case.
/// This is the subquadratic multiplication primitive used by the current
/// product/remainder-tree backend over the existing dalek scalar field.
pub fn multiply_subquadratic(
    left: &[Scalar],
    right: &[Scalar],
) -> (Vec<Scalar>, PolynomialOpCounts) {
    let mut counts = PolynomialOpCounts::default();
    let product = multiply_counted(left, right, &mut counts);
    (product, counts)
}

pub fn multipoint_evaluate(
    polynomial: &[Scalar],
    points: &[Scalar],
) -> Result<(Vec<Scalar>, PolynomialOpCounts), PolynomialError> {
    let (plan, mut counts) = MultipointEvaluationPlan::new(points)?;
    let (values, evaluation_counts) = plan.evaluate(polynomial)?;
    counts += evaluation_counts;
    Ok((values, counts))
}

pub fn interpolate_at_zero_fast(
    shares: &[(Scalar, Scalar)],
    threshold: usize,
) -> Result<(Scalar, PolynomialOpCounts), PolynomialError> {
    if threshold == 0 {
        return Err(PolynomialError::InvalidCoefficientCount);
    }
    if shares.len() != threshold {
        return Err(PolynomialError::WrongShareCount {
            have: shares.len(),
            need: threshold,
        });
    }
    let points = shares.iter().map(|(point, _)| *point).collect::<Vec<_>>();
    let (plan, mut counts) = MultipointEvaluationPlan::new(&points)?;
    let (weights, interpolation_counts) = plan.interpolation_weights_at_zero()?;
    counts += interpolation_counts;
    let mut result = Scalar::ZERO;
    for ((_, value), weight) in shares.iter().zip(weights) {
        result += weight * *value;
        counts.scalar_multiplications += 1;
        counts.scalar_additions += 1;
    }
    Ok((result, counts))
}

const KARATSUBA_BASE: usize = 8;

#[derive(Clone, Debug)]
struct ProductNode {
    polynomial: Vec<Scalar>,
    reversed_divisor_inverse: Vec<Scalar>,
    range_start: usize,
    left: Option<Box<ProductNode>>,
    right: Option<Box<ProductNode>>,
}

impl ProductNode {
    fn build(points: &[Scalar], counts: &mut PolynomialOpCounts) -> Self {
        Self::build_range(points, 0, counts)
    }

    fn build_range(points: &[Scalar], range_start: usize, counts: &mut PolynomialOpCounts) -> Self {
        if points.len() == 1 {
            return Self {
                polynomial: vec![-points[0], Scalar::ONE],
                reversed_divisor_inverse: Vec::new(),
                range_start,
                left: None,
                right: None,
            };
        }
        let middle = points.len() / 2;
        let left = Box::new(Self::build_range(&points[..middle], range_start, counts));
        let right = Box::new(Self::build_range(
            &points[middle..],
            range_start + middle,
            counts,
        ));
        let polynomial = multiply_counted(&left.polynomial, &right.polynomial, counts);
        Self {
            polynomial,
            reversed_divisor_inverse: Vec::new(),
            range_start,
            left: Some(left),
            right: Some(right),
        }
    }

    fn prepare_remainder_plans(
        &mut self,
        counts: &mut PolynomialOpCounts,
    ) -> Result<(), PolynomialError> {
        let maximum_dividend_len = self.polynomial.len().saturating_sub(1);
        match (&mut self.left, &mut self.right) {
            (None, None) => Ok(()),
            (Some(left), Some(right)) => {
                left.prepare_divisor_inverse(maximum_dividend_len, counts)?;
                right.prepare_divisor_inverse(maximum_dividend_len, counts)?;
                left.prepare_remainder_plans(counts)?;
                right.prepare_remainder_plans(counts)
            }
            _ => Err(PolynomialError::InvalidCoefficientCount),
        }
    }

    fn prepare_divisor_inverse(
        &mut self,
        maximum_dividend_len: usize,
        counts: &mut PolynomialOpCounts,
    ) -> Result<(), PolynomialError> {
        if maximum_dividend_len < self.polynomial.len() {
            self.reversed_divisor_inverse.clear();
            return Ok(());
        }
        let quotient_len = maximum_dividend_len - self.polynomial.len() + 1;
        let mut reversed_divisor = self.polynomial.iter().rev().copied().collect::<Vec<_>>();
        reversed_divisor.truncate(quotient_len);
        self.reversed_divisor_inverse = inverse_series(&reversed_divisor, quotient_len, counts)?;
        Ok(())
    }

    fn evaluate_remainder(
        &self,
        remainder: &[Scalar],
        output: &mut [Scalar],
        counts: &mut PolynomialOpCounts,
    ) -> Result<(), PolynomialError> {
        match (&self.left, &self.right) {
            (None, None) => {
                output[self.range_start] = remainder.first().copied().unwrap_or(Scalar::ZERO);
                Ok(())
            }
            (Some(left), Some(right)) => {
                let left_remainder = polynomial_remainder_planned(
                    remainder,
                    &left.polynomial,
                    &left.reversed_divisor_inverse,
                    counts,
                )?;
                let right_remainder = polynomial_remainder_planned(
                    remainder,
                    &right.polynomial,
                    &right.reversed_divisor_inverse,
                    counts,
                )?;
                left.evaluate_remainder(&left_remainder, output, counts)?;
                right.evaluate_remainder(&right_remainder, output, counts)
            }
            _ => Err(PolynomialError::InvalidCoefficientCount),
        }
    }
}

fn evaluate_counted(
    coefficients: &[Scalar],
    point: Scalar,
    counts: &mut PolynomialOpCounts,
) -> Scalar {
    let Some((leading, remaining)) = coefficients.split_last() else {
        return Scalar::ZERO;
    };
    remaining.iter().rev().fold(*leading, |acc, coefficient| {
        counts.scalar_multiplications += 1;
        counts.scalar_additions += 1;
        acc * point + coefficient
    })
}

fn multiply_counted(
    left: &[Scalar],
    right: &[Scalar],
    counts: &mut PolynomialOpCounts,
) -> Vec<Scalar> {
    if left.is_empty() || right.is_empty() {
        return Vec::new();
    }
    let result_len = left.len() + right.len() - 1;
    let padded = left.len().max(right.len()).next_power_of_two();
    let mut left_padded = vec![Scalar::ZERO; padded];
    let mut right_padded = vec![Scalar::ZERO; padded];
    left_padded[..left.len()].copy_from_slice(left);
    right_padded[..right.len()].copy_from_slice(right);
    let mut result = karatsuba_equal(&left_padded, &right_padded, counts);
    result.truncate(result_len);
    trim_polynomial(result)
}

fn karatsuba_equal(
    left: &[Scalar],
    right: &[Scalar],
    counts: &mut PolynomialOpCounts,
) -> Vec<Scalar> {
    debug_assert_eq!(left.len(), right.len());
    let n = left.len();
    if n <= KARATSUBA_BASE {
        counts.schoolbook_calls += 1;
        let mut result = vec![Scalar::ZERO; 2 * n];
        for (i, left_value) in left.iter().enumerate() {
            for (j, right_value) in right.iter().enumerate() {
                result[i + j] += *left_value * *right_value;
                counts.scalar_multiplications += 1;
                counts.scalar_additions += 1;
            }
        }
        return result;
    }
    counts.karatsuba_calls += 1;
    let middle = n / 2;
    let low = karatsuba_equal(&left[..middle], &right[..middle], counts);
    let high = karatsuba_equal(&left[middle..], &right[middle..], counts);
    let mut left_sum = vec![Scalar::ZERO; middle];
    let mut right_sum = vec![Scalar::ZERO; middle];
    for index in 0..middle {
        left_sum[index] = left[index] + left[middle + index];
        right_sum[index] = right[index] + right[middle + index];
        counts.scalar_additions += 2;
    }
    let mut cross = karatsuba_equal(&left_sum, &right_sum, counts);
    for index in 0..cross.len() {
        cross[index] -= low[index] + high[index];
        counts.scalar_additions += 2;
    }
    let mut result = vec![Scalar::ZERO; 2 * n];
    add_shifted(&mut result, &low, 0, counts);
    add_shifted(&mut result, &cross, middle, counts);
    add_shifted(&mut result, &high, 2 * middle, counts);
    result
}

fn add_shifted(
    target: &mut [Scalar],
    values: &[Scalar],
    shift: usize,
    counts: &mut PolynomialOpCounts,
) {
    for (index, value) in values.iter().enumerate() {
        if shift + index < target.len() {
            target[shift + index] += value;
            counts.scalar_additions += 1;
        }
    }
}

fn polynomial_remainder(
    dividend: &[Scalar],
    divisor: &[Scalar],
    counts: &mut PolynomialOpCounts,
) -> Result<Vec<Scalar>, PolynomialError> {
    let dividend = trim_polynomial(dividend.to_vec());
    let divisor = trim_polynomial(divisor.to_vec());
    if divisor.is_empty() || divisor.iter().all(|value| *value == Scalar::ZERO) {
        return Err(PolynomialError::InvalidCoefficientCount);
    }
    if dividend.len() < divisor.len() {
        return Ok(dividend);
    }
    counts.division_calls += 1;
    let quotient_len = dividend.len() - divisor.len() + 1;
    let mut reversed_divisor = divisor.iter().rev().copied().collect::<Vec<_>>();
    reversed_divisor.truncate(quotient_len);
    let inverse = inverse_series(&reversed_divisor, quotient_len, counts)?;
    let reversed_dividend = dividend
        .iter()
        .rev()
        .take(quotient_len)
        .copied()
        .collect::<Vec<_>>();
    let mut reversed_quotient = multiply_counted(&reversed_dividend, &inverse, counts);
    reversed_quotient.resize(quotient_len, Scalar::ZERO);
    reversed_quotient.truncate(quotient_len);
    let quotient = reversed_quotient.into_iter().rev().collect::<Vec<_>>();
    let product = multiply_counted(&quotient, &divisor, counts);
    let mut remainder = dividend;
    remainder.resize(product.len().max(remainder.len()), Scalar::ZERO);
    for (index, value) in product.iter().enumerate() {
        remainder[index] -= value;
        counts.scalar_additions += 1;
    }
    remainder.truncate(divisor.len().saturating_sub(1).max(1));
    Ok(trim_polynomial(remainder))
}

fn polynomial_remainder_planned(
    dividend: &[Scalar],
    divisor: &[Scalar],
    reversed_divisor_inverse: &[Scalar],
    counts: &mut PolynomialOpCounts,
) -> Result<Vec<Scalar>, PolynomialError> {
    let dividend = trim_polynomial(dividend.to_vec());
    if divisor.is_empty() || divisor.iter().all(|value| *value == Scalar::ZERO) {
        return Err(PolynomialError::InvalidCoefficientCount);
    }
    if dividend.len() < divisor.len() {
        return Ok(dividend);
    }
    let quotient_len = dividend.len() - divisor.len() + 1;
    if reversed_divisor_inverse.len() < quotient_len {
        return polynomial_remainder(&dividend, divisor, counts);
    }
    counts.division_calls += 1;
    let reversed_dividend = dividend
        .iter()
        .rev()
        .take(quotient_len)
        .copied()
        .collect::<Vec<_>>();
    let mut reversed_quotient = multiply_counted(
        &reversed_dividend,
        &reversed_divisor_inverse[..quotient_len],
        counts,
    );
    reversed_quotient.resize(quotient_len, Scalar::ZERO);
    reversed_quotient.truncate(quotient_len);
    let quotient = reversed_quotient.into_iter().rev().collect::<Vec<_>>();
    let product = multiply_counted(&quotient, divisor, counts);
    let mut remainder = dividend;
    remainder.resize(product.len().max(remainder.len()), Scalar::ZERO);
    for (index, value) in product.iter().enumerate() {
        remainder[index] -= value;
        counts.scalar_additions += 1;
    }
    remainder.truncate(divisor.len().saturating_sub(1).max(1));
    Ok(trim_polynomial(remainder))
}

fn inverse_series(
    polynomial: &[Scalar],
    length: usize,
    counts: &mut PolynomialOpCounts,
) -> Result<Vec<Scalar>, PolynomialError> {
    if polynomial.is_empty() || polynomial[0] == Scalar::ZERO || length == 0 {
        return Err(PolynomialError::InvalidCoefficientCount);
    }
    let mut inverse = vec![if polynomial[0] == Scalar::ONE {
        Scalar::ONE
    } else {
        polynomial[0].invert()
    }];
    while inverse.len() < length {
        let target = (inverse.len() * 2).min(length);
        let prefix = &polynomial[..polynomial.len().min(target)];
        let mut product = multiply_counted(prefix, &inverse, counts);
        product.resize(target, Scalar::ZERO);
        let mut correction = vec![Scalar::ZERO; target];
        correction[0] = Scalar::from(2u64) - product[0];
        for index in 1..target {
            correction[index] = -product[index];
        }
        counts.scalar_additions += target as u64;
        inverse = multiply_counted(&inverse, &correction, counts);
        inverse.resize(target, Scalar::ZERO);
        inverse.truncate(target);
    }
    Ok(inverse)
}

fn derivative(polynomial: &[Scalar], counts: &mut PolynomialOpCounts) -> Vec<Scalar> {
    if polynomial.len() <= 1 {
        return vec![Scalar::ZERO];
    }
    polynomial
        .iter()
        .enumerate()
        .skip(1)
        .map(|(degree, coefficient)| {
            counts.scalar_multiplications += 1;
            *coefficient * Scalar::from(degree as u64)
        })
        .collect()
}

fn batch_invert(
    values: &[Scalar],
    counts: &mut PolynomialOpCounts,
) -> Result<Vec<Scalar>, PolynomialError> {
    if values.contains(&Scalar::ZERO) {
        return Err(PolynomialError::DuplicatePoint);
    }
    counts.batch_inversions += 1;
    let mut prefixes = Vec::with_capacity(values.len());
    let mut accumulator = Scalar::ONE;
    for value in values {
        prefixes.push(accumulator);
        accumulator *= value;
        counts.scalar_multiplications += 1;
    }
    let mut inverse = accumulator.invert();
    let mut output = vec![Scalar::ZERO; values.len()];
    for index in (0..values.len()).rev() {
        output[index] = inverse * prefixes[index];
        inverse *= values[index];
        counts.scalar_multiplications += 2;
    }
    Ok(output)
}

fn trim_polynomial(mut polynomial: Vec<Scalar>) -> Vec<Scalar> {
    while polynomial.len() > 1 && polynomial.last() == Some(&Scalar::ZERO) {
        polynomial.pop();
    }
    polynomial
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PolynomialError {
    #[error("invalid coefficient count")]
    InvalidCoefficientCount,
    #[error("wrong share count: have {have}, need {need}")]
    WrongShareCount { have: usize, need: usize },
    #[error("duplicate interpolation point")]
    DuplicatePoint,
    #[error("zero is not a valid Shamir evaluation point")]
    ZeroEvaluationPoint,
}
