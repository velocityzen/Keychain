precedencegroup SingleFowardPipe {
    associativity: left
    higherThan: BitwiseShiftPrecedence
}

infix operator |> : SingleFowardPipe

/// Forward pipe operator
public func |> <A, Z>(lhs: A, rhs: (A) -> Z) -> Z {
    return rhs(lhs)
}

/// Forward pipe operator
public func |> <A, Z, Error>(lhs: Result<A, Error>, rhs: (A) -> Z) -> Result<Z, Error> {
    return lhs.map(rhs)
}
