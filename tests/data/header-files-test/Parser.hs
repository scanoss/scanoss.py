-- |
-- Module      : Text.Parsec.Combinator
-- Copyright   : (c) 2024 Daan Leijen, Paolo Martini
-- License     : BSD-3-Clause
--
-- Maintainer  : asr@eafit.edu.co
-- Stability   : provisional
-- Portability : portable
--
-- Commonly used generic parser combinators.

module Text.Parsec.Combinator
  ( choice
  , count
  , between
  , option
  , optional
  , sepBy
  , sepBy1
  , many1
  , chainl
  , chainl1
  , chainr
  , chainr1
  , eof
  , notFollowedBy
  , manyTill
  , lookAhead
  ) where

import Text.Parsec.Prim (Parser, (<|>), try, unexpected, lookAhead)

-- | @choice ps@ tries to apply the parsers in the list @ps@ in order,
-- until one of them succeeds. Returns the value of the succeeding parser.
choice :: [Parser a] -> Parser a
choice = foldr (<|>) (unexpected "no match")

-- | @count n p@ parses @n@ occurrences of @p@.
count :: Int -> Parser a -> Parser [a]
count n p
  | n <= 0    = return []
  | otherwise = sequence (replicate n p)

-- | @between open close p@ parses @open@, followed by @p@ and @close@.
-- Returns the value returned by @p@.
between :: Parser open -> Parser close -> Parser a -> Parser a
between open close p = do
  _ <- open
  x <- p
  _ <- close
  return x

-- | @option x p@ tries to apply parser @p@. If @p@ fails without
-- consuming input, it returns the value @x@, otherwise the value
-- returned by @p@.
option :: a -> Parser a -> Parser a
option x p = p <|> return x

-- | @optional p@ tries to apply parser @p@. It will parse @p@ or nothing.
-- It only fails if @p@ fails after consuming input.
optional :: Parser a -> Parser ()
optional p = (p >> return ()) <|> return ()

-- | @sepBy p sep@ parses zero or more occurrences of @p@, separated
-- by @sep@. Returns a list of values returned by @p@.
sepBy :: Parser a -> Parser sep -> Parser [a]
sepBy p sep = sepBy1 p sep <|> return []

-- | @sepBy1 p sep@ parses one or more occurrences of @p@, separated
-- by @sep@. Returns a list of values returned by @p@.
sepBy1 :: Parser a -> Parser sep -> Parser [a]
sepBy1 p sep = do
  x <- p
  xs <- many (sep >> p)
  return (x : xs)

-- | @many1 p@ applies the parser @p@ one or more times.
many1 :: Parser a -> Parser [a]
many1 p = do
  x <- p
  xs <- many p
  return (x : xs)

-- | @chainl p op x@ parses zero or more occurrences of @p@,
-- separated by @op@. Returns a value obtained by a left associative
-- application of all functions returned by @op@ to the values
-- returned by @p@. If there are zero occurrences of @p@, the value
-- @x@ is returned.
chainl :: Parser a -> Parser (a -> a -> a) -> a -> Parser a
chainl p op x = chainl1 p op <|> return x

-- | @chainl1 p op@ parses one or more occurrences of @p@,
-- separated by @op@. Returns a value obtained by a left associative
-- application of all functions returned by @op@.
chainl1 :: Parser a -> Parser (a -> a -> a) -> Parser a
chainl1 p op = do
  x <- p
  rest x
  where
    rest x = (do f <- op
                 y <- p
                 rest (f x y))
             <|> return x