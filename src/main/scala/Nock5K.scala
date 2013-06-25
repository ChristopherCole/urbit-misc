package capeanntool.urbit.nock

import java.io.{BufferedReader, InputStreamReader, File}
import scala.collection.immutable.{PagedSeq, Stack, Queue}
import scala.collection.mutable.ListBuffer
import scala.util.parsing.combinator.syntactical.StandardTokenParsers
import scala.util.parsing.combinator.token.StdTokens
import scala.util.parsing.input.PagedSeqReader

object Nock5K {
  def usage(message: Option[String] = None) = {
    message match {
      case Some(message) => Console.err.println(message)
      case None =>
    }
    Console.err.println(
"""Usage: Nock5K [options] [<file1> <file2> ...]

  --enable-tracing
        turn tracing on
  --disable-tracing
        turn tracing off
  --help
        prints this usage text
  <file1> <file2> ...
        files to interpret (use "-" for standard input)
"""
    )
    sys.exit(1)
  }

  def main(args: Array[String]) = {
    val traceEnv = sys.env.getOrElse("NOCK_TRACE", "false")
    var trace = !((traceEnv equalsIgnoreCase "no") || (traceEnv == "0") || (traceEnv equalsIgnoreCase "false"))
    var inputs = new ListBuffer[(Option[File], PagedSeq[Char])]
    args foreach {
      arg => {
	arg match {
	  case "--help" => usage()
	  case "--enable-tracing" => trace = true
	  case "--disable-tracing" => trace = false
	  case "-" => inputs += ((None, PagedSeq fromReader new BufferedReader(new InputStreamReader(System.in))))
	  case file => {
	    if (file.startsWith("-"))
	      usage(Some("Unknown option: '" + file + "'"))
	    else
	      { val f = new File(file) ; if (f.exists) inputs += ((Some(f), PagedSeq fromFile file)) else usage(Some("File not found: " + file)) }
	  }
	}
      }
    }
    if (inputs.isEmpty) usage(Some("No files specified"))
    (new Nock5K(inputs.toSeq, trace)).run()
  }
}

class Nock5K(val inputs: Seq[(Option[File], PagedSeq[Char])], val trace: Boolean)  extends StandardTokenParsers {
  val Zero  = Atom(BigInt(0)) ; val One   = Atom(BigInt(1))  ; val Two   = Atom(BigInt(2))
  val Three = Atom(BigInt(3)) ; val Four  = Atom(BigInt(4))  ; val Five  = Atom(BigInt(5))
  val Six   = Atom(BigInt(6)) ; val Seven = Atom(BigInt(7))  ; val Eight = Atom(BigInt(8))
  val Nine  = Atom(BigInt(9)) ; val Ten   = Atom(BigInt(10)) 

  val ZeroOne = Cell(Zero, One) ; val OneZero = Cell(One, Zero)

  /* tracing/debugging */
  var indent = 0
  def cite(line: Int) = if (trace) print("   #" + line)
  def trace(s: String, in: Noun, o: => Noun): Noun = {
    if (trace) {
      if (indent > 0)
	println()
      for (i <- 0 until indent) print("    ")
      print("-> " + s + in)
      indent += 1
    }
    val out = o
    if (trace) {
      println()
      indent -= 1
      for (i <- 0 until indent) print("    ")
      print("<- " + out)
      if (indent == 0)
	println()
    }
    out
  }
  
  /* representation */
  sealed abstract class Noun { def toString(brackets: Boolean): String = toString() }
  case class Atom(value: BigInt) extends Noun { override def toString = value.toString }
  case class Cell(left: Noun, right: Noun) extends Noun { 
    override def toString(brackets: Boolean) = (if (brackets) "[" else "") + left + " " + right.toString(false) + (if (brackets) "]" else "")
    override def toString = toString(true)
  }
  def toCell(list: List[Noun]): Cell = {
    list match {
      case a :: b :: Nil => Cell(a, b)
      case a :: b => Cell(a, toCell(b))
    }
  }

  /* parser */
  lexical.delimiters += ("[", "]")
  def atom = numericLit ^^ { s => Atom(BigInt(s)) }
  def cell = ( ( "[" ~> rep1(atom | noun) <~ "]" ) ^^ { toCell(_) } )
  def noun: Parser[Noun] = cell | atom

  def run() {
    inputs foreach {
      input => {
	println(input._1 match { case Some(file) => "file: " + file case None => "file: standard input" })
	var tokens = new lexical.Scanner(new PagedSeqReader(input._2))
	phrase(noun)(tokens) match {
	  case Success(tree, _) => println(nock(tree))
	  case e: NoSuccess => Console.err.println(e)
	}
      }
    }
  }

  /* interpreter */
  def crash(in: Noun): Noun = { throw new Exception("Crash: " + in) }
  def slash(in: Noun): Noun = {
    trace("/", in, in match {
      case a: Atom => { cite(34) ; crash(a) }
      case Cell(One, a) => { cite(10) ; a }
      case Cell(Two, Cell(a, _)) => { cite(11) ; a }
      case Cell(Three, Cell(_, b)) => { cite(12) ; b }
      case Cell(Atom(index), b) if (index % 2) == 0 => { cite(13) ; slash(Cell(Two, slash(Cell(Atom(index / 2), b)))) }
      case Cell(Atom(index), b) => { cite(14) ; slash(Cell(Three, slash(Cell(Atom((index - 1) / 2), b)))) }
      case noMatch => crash(noMatch)
    })
  }
  def cell(in: Noun): Noun = {
    trace("?", in, in match {
      case a: Atom => { cite(5) ; One }
      case na => { cite(4) ; Zero }
    })
  }
  def inc(in: Noun): Noun = {
    trace("+", in, in match {
      case Atom(n) => { cite(6) ; Atom(n + 1) }
      case noMatch => crash(noMatch)
    })
  }
  def equals(in: Noun): Noun = { 
    trace("=", in, in match {
      case Cell(left: Atom, right: Atom) if (left == right) => { cite(7) ; Zero }
      case Cell(left: Atom, _) => { cite(8) ; One } // QUESTION: should crash on non-atom?
      case a: Atom => { cite(33) ; crash(a) }
      case noMatch => crash(noMatch)
    })
  }
  def cond(a: Noun, b: Noun, c: Noun, d: Noun): Noun = {
    val reduce = false
    if (reduce) 
      nock(Cell(a, Cell(Two, Cell(Cell(Zero, One), Cell(Two, Cell(Cell(One, Cell(c, d)), Cell(OneZero, Cell(Two, Cell(Cell(One, Cell(Two, Three)), Cell(OneZero, Cell(Four, Cell(Four, b))))))))))))
    else {
      nock(Cell(a, b)) match {
	case Zero => nock(Cell(a, c))
	case One => nock(Cell(a, d))
	case noMatch => crash(noMatch)
      }
    }
  }
  def nock(in: Noun): Noun = {
    trace("*", in, in match {
      case Cell(a, Cell(Cell(b, c), d)) => { cite(16) ; Cell(nock(Cell(a, Cell(b, c))), nock(Cell(a, d))) }
      case Cell(a, Cell(Zero, b)) => { cite(18) ; slash(Cell(b, a)) }
      case Cell(a, Cell(One, b)) => { cite(19) ; b }
      case Cell(a, Cell(Two, Cell(b, c))) => { cite(20) ; nock(Cell(nock(Cell(a, b)), nock(Cell(a, c)))) }
      case Cell(a, Cell(Three, b)) => { cite(21) ; cell(nock(Cell(a, b))) }
      case Cell(a, Cell(Four, b)) => { cite(22) ; inc(nock(Cell(a, b))) }
      case Cell(a, Cell(Five, b)) => { cite(23) ; equals(nock(Cell(a, b))) }
      case Cell(a, Cell(Six, Cell(b, Cell(c, d)))) => { cite(25) ; cond(a, b, c, d) }
      case Cell(a, Cell(Seven, Cell(b, c))) => { cite(26) ; nock(Cell(a, Cell(Two, Cell(b, Cell(One, c))))) }
      case Cell(a, Cell(Eight, Cell(b, c))) => { cite(27) ; nock(Cell(a, Cell(Seven, Cell(Cell(Cell(Seven, Cell(ZeroOne, b)), ZeroOne), c)))) }
      case Cell(a, Cell(Nine, Cell(b, c))) => { cite(28) ; nock(Cell(a, Cell(Seven, Cell(c, Cell(Two, Cell(ZeroOne, Cell(Zero, b))))))) }
      case Cell(a, Cell(Ten, Cell(Cell(b, c), d))) => { cite(29) ; nock(Cell(a, Cell(Eight, Cell(c, Cell(Seven, Cell(Cell(Zero, Two), d)))))) }
      case Cell(a, Cell(Ten, Cell(b, c))) => { cite(29) ; nock(Cell(a, c)) }
      case a: Atom => { cite(35) ; crash(a) }
      case noMatch => crash(noMatch)
    })
  }
}
