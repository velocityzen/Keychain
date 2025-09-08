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

infix operator |>> : SingleFowardPipe

/// Pipe into second argument
public func |>> <A, B, Z>(lhs: B, rhs: ((A, B) -> Z, A)) -> Z {
    return rhs.0(rhs.1, lhs)
}

infix operator |>>> : SingleFowardPipe

/// Pipe into third argument
public func |>>> <A, B, C, Z>(lhs: C, rhs: (((A, B, C) -> Z), A, B)) -> Z {
    return rhs.0(rhs.1, rhs.2, lhs)
}

infix operator |< : SingleFowardPipe

/// Pipe into last argument
public func |< <A, Z>(lhs: A, rhs: (A) -> Z) -> Z {
    return rhs(lhs)
}
