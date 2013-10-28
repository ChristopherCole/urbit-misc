import java.io.{BufferedReader, InputStreamReader, File}
import scala.collection.immutable.{PagedSeq, Stack, Queue}
import scala.collection.mutable.ListBuffer
import scala.util.parsing.combinator.syntactical.StandardTokenParsers
import scala.util.parsing.combinator.token.StdTokens
import scala.util.parsing.input.PagedSeqReader
import scala.util.control.TailCalls._

object Nock5K {
  def usage(message: Option[String] = None) = {
    message match {
      case Some(message) => Console.err.println(message)
      case None =>
    }
    Console.err.println(
"""Usage: Nock5K [options] [<file1> <file2> ...]

--help
prints this usage text
<file1> <file2> ...
files to interpret (use "-" for standard input)
"""
    )
    sys.exit(1)
  }

  def main(args: Array[String]) = {
    var inputs = new ListBuffer[(Option[File], PagedSeq[Char])]
    args foreach {
      arg => {
        arg match {
          case "--help" => usage()
          case "-" => {
            inputs += ((None, PagedSeq fromReader new BufferedReader(
              new InputStreamReader(System.in))))
          }
          case file => {
            if (file.startsWith("-"))
              usage(Some("Unknown option: '" + file + "'"))
            else {
              val f = new File(file)
              if (f.exists) 
                inputs += ((Some(f), PagedSeq fromFile file))
              else
                usage(Some("File not found: " + file)) 
            }
          }
        }
      }
    }

    if (inputs.isEmpty) usage(Some("No files specified"))

    (new Nock5K(inputs.toSeq)).run()
  }
}

class Nock5K(val inputs: Seq[(Option[File], PagedSeq[Char])])
  extends StandardTokenParsers {
  val Zero = Atom(BigInt(0))
  val One = Atom(BigInt(1))
  val Two = Atom(BigInt(2))
  val Three = Atom(BigInt(3))
  val Four = Atom(BigInt(4))
  val Five = Atom(BigInt(5))
  val Six = Atom(BigInt(6))
  val Seven = Atom(BigInt(7))
  val Eight = Atom(BigInt(8))
  val Nine = Atom(BigInt(9))
  val Ten = Atom(BigInt(10))
  val ZeroOne = Cell(Zero, One)
  val OneZero = Cell(One, Zero)

  /* representation */
  sealed abstract class Noun {
    def toString(brackets: Boolean): String = toString()
  }

  case class Atom(value: BigInt) extends Noun {
    override def toString = value.toString
  }

  case class Cell(left: Noun, right: Noun) extends Noun {
    override def toString(brackets: Boolean): String = {
      (if (brackets) "[" else "") + left +
      " " +
      right.toString(false) + (if (brackets) "]" else "")
    }

    override def toString = toString(true)
  }

  def toCell(list: List[Noun]): Cell = {
    list match {
      case a :: b :: Nil => Cell(a, b)
      case a :: b => Cell(a, toCell(b))
    }
  }

  lexical.delimiters += ("[", "]")
  def atom = numericLit ^^ { s => Atom(BigInt(s)) }
  def cell = ( ( "[" ~> rep1(atom | noun) <~ "]" ) ^^ { toCell(_) } )
  def noun: Parser[Noun] = cell | atom

  def run() {
    inputs foreach {
      input => {
        println(input._1 match {
          case Some(file) => 
            "file: " + file case None => "file: standard input" })
        var tokens = new lexical.Scanner(new PagedSeqReader(input._2))
        phrase(noun)(tokens) match {
         case Success(tree, _) => {
           if (false) {
             println("Warming up")
             for (i <- 0 until 20) {
               println(i)
               nock(tree).result
             }
           }
           val start = System.nanoTime()
           val result = nock(tree).result
           val end = System.nanoTime()
           println(result)
           println("Time = " + (end - start).asInstanceOf[Double] / 1000000000)
         }
         case e: NoSuccess => Console.err.println(e)
        }
      }
    }
  }

  def crash(in: Noun): TailRec[Noun] = { throw new Exception("Crash: " + in) }

  def slash(in: Noun): TailRec[Noun] = {
    in match {
      case a: Atom => tailcall(crash(a))
      case Cell(One, a) => done(a)
      case Cell(Two, Cell(a, b)) => done(a)
      case Cell(Three, Cell(a, b)) => done(b)
      case Cell(Atom(index), b) if (index % 2) == 0 => tailcall(slash(Cell(Two, slash(Cell(Atom(index / 2), b)).result)))
      case Cell(Atom(index), b) => tailcall(slash(Cell(Three, slash(Cell(Atom((index - 1) / 2), b)).result)))
      case noMatch => tailcall(crash(noMatch))
    }
  }

  def cell(in: Noun): TailRec[Noun] = {
    in match {
      case a: Atom => done(One)
      case na => done(Zero)
    }
  }

  def inc(in: Noun): TailRec[Noun] = {
    in match {
      case Atom(n) => done(Atom(n + 1))
      case noMatch => tailcall(crash(noMatch))
    }
  }

  def equals(in: Noun): TailRec[Noun] = {
    in match {
      case Cell(left: Atom, right: Atom) if (left == right) => done(Zero)
      case Cell(left: Atom, _) => done(One) // QUESTION: should crash on non-atom?
      case a: Atom => tailcall(crash(a))
      case noMatch => tailcall(crash(noMatch))
    }
  }

  def cond(a: Noun, b: Noun, c: Noun, d: Noun): TailRec[Noun] = {
    val reduce = false
    if (reduce)
      tailcall(nock(Cell(a, Cell(Two, Cell(Cell(Zero, One), Cell(Two, Cell(Cell(One, Cell(c, d)), Cell(OneZero, Cell(Two, Cell(Cell(One, Cell(Two, Three)), Cell(OneZero, Cell(Four, Cell(Four, b)))))))))))))
    else {
      nock(Cell(a, b)).result match {
        case Zero => tailcall(nock(Cell(a, c)))
        case One => tailcall(nock(Cell(a, d)))
        case noMatch => tailcall(crash(noMatch))
      }
    }
  }

  def nock(in: Noun): TailRec[Noun] = {
    in match {
      case Cell(a, Cell(Cell(b, c), d)) => done(Cell(nock(Cell(a, Cell(b, c))).result, nock(Cell(a, d)).result))
      case Cell(a, Cell(Zero, b)) => tailcall(slash(Cell(b, a)))
      case Cell(a, Cell(One, b)) => done(b)
      case Cell(a, Cell(Two, Cell(b, c))) => tailcall(nock(Cell(nock(Cell(a, b)).result, nock(Cell(a, c)).result)))
      case Cell(a, Cell(Three, b)) => tailcall(cell(nock(Cell(a, b)).result))
      case Cell(a, Cell(Four, b)) => tailcall(inc(nock(Cell(a, b)).result))
      case Cell(a, Cell(Five, b)) => tailcall(equals(nock(Cell(a, b)).result))
      case Cell(a, Cell(Six, Cell(b, Cell(c, d)))) => tailcall(cond(a, b, c, d))
      case Cell(a, Cell(Seven, Cell(b, c))) => tailcall(nock(Cell(a, Cell(Two, Cell(b, Cell(One, c))))))
      case Cell(a, Cell(Eight, Cell(b, c))) => tailcall(nock(Cell(a, Cell(Seven, Cell(Cell(Cell(Seven, Cell(ZeroOne, b)), ZeroOne), c)))))
      case Cell(a, Cell(Nine, Cell(b, c))) => tailcall(nock(Cell(a, Cell(Seven, Cell(c, Cell(Two, Cell(ZeroOne, Cell(Zero, b))))))))
      case Cell(a, Cell(Ten, Cell(Cell(b, c), d))) => tailcall(nock(Cell(a, Cell(Eight, Cell(c, Cell(Seven, Cell(Cell(Zero, Two), d)))))))
      case Cell(a, Cell(Ten, Cell(b, c))) => tailcall(nock(Cell(a, c)))
      case a: Atom => tailcall(crash(a))
      case noMatch => tailcall(crash(noMatch))
    }
  }
}
