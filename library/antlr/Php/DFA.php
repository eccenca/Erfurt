<?php
/*
 [The "BSD licence"]
 Copyright (c) 2005-2008 Terence Parr
 Copyright (c) 2009 Yauhen Yakimovich
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. The name of the author may not be used to endorse or promote products
    derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/** A DFA implemented as a set of transition tables.
 *
 *  Any state that has a semantic predicate edge is special; those states
 *  are generated with if-then-else structures in a specialStateTransition()
 *  which is generated by cyclicDFA template.
 *
 *  There are at most 32767 states (16-bit signed short).
 *  Could get away with byte sometimes but would have to generate different
 *  types and the simulation code too.  For a point of reference, the Java
 *  lexer's Tokens rule DFA has 326 states roughly.
 */
class DFA {
    protected $eot;
    protected $eof;
    protected $min;
    protected $max;
    protected $accept;
    protected $special;
    protected $transition;

    protected $decisionNumber;

    /** Which recognizer encloses this DFA?  Needed to check backtracking */
    protected $recognizer;

    public $debug = false;

    /** From the input stream, predict what alternative will succeed
     *  using this DFA (representing the covering regular approximation
     *  to the underlying CFL).  Return an alternative number 1..n.  Throw
     *  an exception upon error.
     */
    //TODO: This is a hackish way of doing a try finally, replace this by bunching up the returns.
    //Possibly rewrite  predict. There is one more place i might need to fix, where i thought
    //try{}catch(ex){[work]; throw ex}; [work]; would be the same as a try finally;

    public function predict($input) {
        if ($input === null)
            throw new Exception("input object is a null pointer");
        if (!is_object($input))
            throw new Exception("input is not an object");
        if ( $this->debug ) {
            echo "Enter DFA.predict for decision ".$this->decisionNumber."\n";
        }
        $mark = $input->mark(); // remember where decision started in input
        try {
            $ret = $this->_predict($input);
        }
        catch(Exception $e) {
            $input->rewind($mark);
            throw $e;
        }
        $input->rewind($mark);
        return $ret;
    }

    public function _predict($input) {
        $s = 0; // we always start at s0
        while ( true ) {
            if ( $this->debug ) echo "DFA ".$this->decisionNumber." state ".$s." LA(1)=".$input->LA(1)."(".chr($input->LA(1))."), index=".$input->index()."\n";
            $specialState = $this->special[$s];
            if ( $specialState>=0 ) {
                if ( $this->debug ) {
                    echo "DFA ".$this->decisionNumber." state ".$s." is special state ".$specialState."\n";
                }
                $s = $this->specialStateTransition($specialState, $input);
                if ( $this->debug ) {
                    echo "DFA ".$this->decisionNumber." returns from special state ".$specialState." to ".$s."\n";
                }
                if ( $s==-1 ) {
                    $this->noViableAlt($s, $input);
                    return 0;
                }
                $input->consume();
                continue;
            }

            if ( $this->accept[$s] >= 1 ) {
                if ( $this->debug ) echo "accept; predict ".$this->accept[$s]." from state ".$s."\n";
                return $this->accept[$s];
            }
            // look for a normal char transition
            $c = $input->LA(1); // -1 == \uFFFF, all tokens fit in 65000 space
            if ($c>=$this->min[$s] && $c<=$this->max[$s]) {
                $snext = $this->transition[$s][$c-$this->min[$s]]; // move to next state
                if ( $snext < 0 ) {
                // was in range but not a normal transition
                // must check EOT, which is like the else clause.
                // eot[s]>=0 indicates that an EOT edge goes to another
                // state.
                    if ( $this->eot[$s]>=0 ) {  // EOT Transition to accept state?
                        if ( $this->debug ) echo "EOT transition\n";
                        $s = $this->eot[$s];
                        $input->consume();
                        // TODO: I had this as return accept[eot[s]]
                        // which assumed here that the EOT edge always
                        // went to an accept...faster to do this, but
                        // what about predicated edges coming from EOT
                        // target?
                        continue;
                    }
                    $this->noViableAlt($s,$input);
                    return 0;
                }
                $s = $snext;
                $input->consume();
                continue;
            }
            if ( $this->eot[$s]>=0 ) {  // EOT Transition?
                if ( $this->debug ) echo "EOT transition\n";
                $s = $this->eot[$s];
                $input->consume();
                continue;
            }
            if ( $c==TokenConst::$EOF && $this->eof[$s]>=0 ) {  // EOF Transition to accept state?
                if ( $this->debug ) echo "accept via EOF; predict ".$this->accept[$this->eof[$s]]." from ".$this->eof[$s]."\n";
                return $this->accept[$this->eof[$s]];
            }
            // not in range and not EOF/EOT, must be invalid symbol
            if ( $this->debug ) {
                echo("min[".$s."]=".$this->min[$s]);
                echo("max[".$s."]=".$this->max[$s]);
                echo("eot[".$s."]=".$this->eot[$s]);
                echo("eof[".$s."]=".$this->eof[$s]);
                echo "\n";
            }
            $this->noViableAlt($s, $input);
            return 0;
        }

    }

    function noViableAlt($s, $input) {
        if ($this->recognizer->state->backtracking>0) {
            $this->recognizer->state->failed=true;
            return;
        }
        $nvae =
            new NoViableAltException($this->getDescription(),
            $this->decisionNumber,
            $s,
            $input);
        $this->error($nvae);
        throw $nvae;
    }

    /** A hook for debugging interface */
    protected function error($nvae) { ; }

    function specialStateTransition($s, IntStream $input) {
        return -1;
    }

    public function getDescription() {
        return "n/a";
    }

    /** Given a String that has a run-length-encoding of some unsigned shorts
     *  like "\1\2\3\9", convert to short[] {2,9,9,9}.  We do this to avoid
     *  static short[] which generates so much init code that the class won't
     *  compile. :(
     */
    public static function unpackRLE($encodedArray, $unsigned=false) {
		$data = array();
        for ($i=0,$len=sizeof($encodedArray); $i<$len; $i+=2) {
            $n = $encodedArray[$i];
            // limit number of transitions, or parsing time >3 sec?!
            if($n>500) continue;
            $v = $encodedArray[$i+1];
			$intValue = $unsigned||(($v&0x8000)==0)?$v:-(0x10000 - $v);
            for ($j=1; $j<=$n; ++$j) {
                $data[] = $intValue;
            }
        }
        return $data;
    }

    /**  GetToken is used as a wrap arround getToken method in recognizer,
     *   because of code generation details in Php.stg
     *
     **/
    function getToken($name) {
        return $this->recognizer->getToken($name);
    }
}

?>
