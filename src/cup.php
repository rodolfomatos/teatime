<?php

// Port of https://github.com/Alemalakra/xWAF to composer
namespace rodolfomatos\teatime;
class cup
{
	//------------------------------------------------------------------
    public function drink($comment = "It's teatime!")
    {
        @$this->writeToLog($comment);
	return $comment;
    }
    public function start_security(){
		/* prevent XSS. */
		$_GET   = filter_input_array(INPUT_GET, FILTER_SANITIZE_STRING);
		$_POST  = filter_input_array(INPUT_POST, FILTER_SANITIZE_STRING);
	}
    public function html_headers($nocache=1,$click=1,$xss=1,$nosniff=1) {
		if($nocache){
				// No-cache
				header('Expires: Tue, 01 Jan 2000 00:00:00 GMT');
				header('Last-Modified: ' . gmdate('D, d M Y H:i:s') . ' GMT');
				header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
				header('Cache-Control: post-check=0, pre-check=0', false);
				header('Pragma: no-cache');
		}
		if($click){
				// Security: Clickjacking
				header('X-Frame-Options: DENY');
		}
		if($xss){
				// Security: XSS-Protection
				header('X-XSS-Protection: 1; mode=block');
		}
		if($nosniff){
				// Security: inform browsers that they should not do MIME type sniffing
				header('X-Content-Type-Options: nosniff');
				header('X-Download-Options: noopen ');
				header('Referrer-Policy: same-origin');
		}
	}
	/*
     * Write to a LOG file the following:
     * [<timestamp>][<event>][<request>][<userid>][<remote_address>][<host>][<referer>][<session_id>]
	*/
	public function writeToLog($event, $logfile='/var/log/teatime.log') {
			try {
				if(!file_exists($logfile)) {
						$log="#<?php die('Forbidden.'); ?>\n";
						$log .= "#[<timestamp>][<event>][<request>][<userid>][<remote_address>][<host>][<referer>][<session_id>]\n";
				} else {
						$log="";
				}
				$time = date('d/m/Y_H:i:s', time());
				$ip = $_SERVER["REMOTE_ADDR"]; // Get the IP from superglobal
				$host = gethostbyaddr($ip);
				$request = $_SERVER['REQUEST_SCHEME']."://".$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'];
				if(isset($_SERVER['HTTP_REFERER'])){
						$referer = $_SERVER['HTTP_REFERER'];
				} else {
						$referer = "";
				}
				if(isset($_SERVER['UPortoNMec']) && ($_SERVER['UPortoNMec']!==NULL)){
						$s=$_SERVER['UPortoNMec'];
				} else {
						$s="";
				}
				$log .= "[".$time."] [".$event."] [".$request."] [".$s."] [".$ip."] [".$host."] [".$referer."] [".session_id()."]\n";
				file_put_contents($logfile, $log, FILE_APPEND | LOCK_EX);
			} catch (Exception $err) {
					print_r($err->getMessage());
			}
	}
	/*
	 * Performs a safe redirect to another url
	 */
	 
	public function safeRedirect($url, $exit = TRUE) {
                try {
                        // Only use the header redirection if headers are not already sent
                        if (headers_sent() !== true) {
                                
                                if (strlen(session_id()) > 0) // if using sessions
                                {
                                        session_regenerate_id(true); // avoids session fixation attacks
                                        session_write_close(); // avoids having sessions lock other requests
                                }               
                                
                                header('HTTP/1.1 301 Moved Permanently');
                                header('Location: ' . $url);
                                // Optional workaround for an IE bug (thanks Olav)
                                header("Connection: close");
                                exit;
                        }
                        // HTML/JS Fallback:
                        // If the header redirection did not work, try to use various methods other methods
                        print '<html>';
                        print '<head><title>Redirecting you...</title>';
                        print '<meta http-equiv="refresh" content="0;url=' . $url . '" />';
                        print '</head>';
                        print '<body onload="location.replace(\'' . $url . '\')">';
                        // If the javascript and meta redirect did not work,
                        // the user can still click this link
                        print 'You should be redirected to this URL:<br />';
                        print "<a href='$url'>$url</a><br /><br />";
                        print 'If you are not, please click on the link above.<br />';
                        print '</body>';
                        print '</html>';
                        // Stop the script here (optional)
                        if ($exit) {
                                exit;
                        }
                } catch (Exception $err) {
                        return $err->getMessage();
                }
        }	
	//------------------------------------------------------------------

    function __construct() {
		$this->IPHeader = "REMOTE_ADDR";
		$this->CookieCheck = true;
		$this->CookieCheckParam = 'username';
		return true;
	}
	function shorten_string($string, $wordsreturned) {
		$retval = $string;
		$array = explode(" ", $string);
		if (count($array)<=$wordsreturned){
			$retval = $string;
		} else {
			array_splice($array, $wordsreturned);
			$retval = implode(" ", $array)." ...";
		}
		return $retval;
	}
	function vulnDetectedHTML($Method, $BadWord, $DisplayName, $TypeVuln) {
		header('HTTP/1.0 403 Forbidden');
		@$this->writeToLog('Request Blocked');
		//@$this->safeRedirect('/418.php');
		eval(gzuncompress(base64_decode('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')));

		die('Your request was blocked. Have a nice day.'); // Block request.
	}
	function getArray($Type) {
		switch ($Type) {
			case 'SQL':
				return array(
							"'",
							'´',
							'SELECT FROM',
							'SELECT * FROM',
							'ONION',
							'union',
							'UNION',
							'UDPATE users SET',
							'WHERE username',
							'DROP TABLE',
							'0x50',
							'mid((select',
							'union(((((((',
							'concat(0x',
							'concat(',
							'OR boolean',
							'or HAVING',
							"OR '1", # Famous skid Poc. 
							'0x3c62723e3c62723e3c62723e',
							'0x3c696d67207372633d22',
							'+#1q%0AuNiOn all#qa%0A#%0AsEleCt',
							'unhex(hex(Concat(',
							'Table_schema,0x3e,',
							'0x00', // \0  [This is a zero, not the letter O]
							'0x08', // \b
							'0x09', // \t
							'0x0a', // \n
							'0x0d', // \r
							'0x1a', // \Z
							'0x22', // \"
							'0x25', // \%
							'0x27', // \'
							'0x5c', // \\
							'0x5f'  // \_
							);
				break;
			case 'XSS':
				return array('<img',
						'img>',
						'<image',
						'document.cookie',
						'onerror()',
						'script>',
						'<script',
						'alert(',
						'window.',
						'String.fromCharCode(',
						'javascript:',
						'onmouseover="',
						'<BODY onload',
						'<style',
						'svg onload');
				break;
			
			default:
				return false;
				break;
		}
	}
	function arrayFlatten(array $array) {
	    $flatten = array();
	    array_walk_recursive($array, function($value) use(&$flatten) {
	        $flatten[] = $value;
	    });
	    return $flatten;
	}
	function sqlCheck($Value, $Method, $DisplayName) {
		// For false alerts.
		$Replace = array("can't" => "cant",
						"don't" => "dont");
		foreach ($Replace as $key => $value_rep) {
			$Value = str_replace($key, $value_rep, $Value);
		}
		$BadWords = $this->getArray('SQL');
		foreach ($BadWords as $BadWord) {
			if (strpos(strtolower($Value), strtolower($BadWord)) !== false) {
				// String contains some Vuln.
				$this->vulnDetectedHTML($Method, $BadWord, $Value, 'SQL Injection');
			}
		}
	}
	function xssCheck($Value, $Method, $DisplayName) {
		// For false alerts.
		$Replace = array("<3" => ":heart:");
		foreach ($Replace as $key => $value_rep) {
			$Value = str_replace($key, $value_rep, $Value);
		}
		$BadWords = $this->getArray('XSS');

		foreach ($BadWords as $BadWord) {
			if (strpos(strtolower($Value), strtolower($BadWord)) !== false) {
			    // String contains some Vuln.

				$this->vulnDetectedHTML($Method, $BadWord, $DisplayName, 'XSS (Cross-Site-Scripting)');
			}
		}
	}
	function is_html($string) {
		return $string != strip_tags($string) ? true:false;

	}
	function santizeString($String) {
		$String = escapeshellarg($String);
		$String = htmlentities($String);
		$XSS = $this->getArray('XSS');
		foreach ($XSS as $replace) {
			$String = str_replace($replace, '', $String);
		}
		$SQL = $this->getArray('SQL');
		foreach ($SQL as $replace) {
			$String = str_replace($replace, '', $String);
		}
		return $String;
	}
	function htmlCheck($value, $Method, $DisplayName) {
		if ($this->is_html(strtolower($value)) !== false) {
			// HTML Detected!
			$this->vulnDetectedHTML($Method, "HTML CHARS", $DisplayName, 'XSS (HTML)');
		}
	}
	function arrayValues($Array) {
		return array_values($Array);
	}
	public function checkGET() {
		foreach ($_GET as $key => $value) {
			if (is_array($value)) {
				$flattened = $this->arrayFlatten($value);
				foreach ($flattened as $sub_key => $sub_value) {
					$this->sqlCheck($sub_value, "_GET", $sub_key);
					$this->xssCheck($sub_value, "_GET", $sub_key);
					$this->htmlCheck($sub_value, "_GET", $sub_key);
				}
			} else {
				$this->sqlCheck($value, "_GET", $key);
				$this->xssCheck($value, "_GET", $key);
				$this->htmlCheck($value, "_GET", $key);
			}
		}
	}
	public function checkPOST() {
		foreach ($_POST as $key => $value) {
			if (is_array($value)) {
				$flattened = $this->arrayFlatten($value);
				foreach ($flattened as $sub_key => $sub_value) {
					$this->sqlCheck($sub_value, "_POST", $sub_key);
					$this->xssCheck($sub_value, "_POST", $sub_key);
					$this->htmlCheck($sub_value, "_POST", $sub_key);
				}
			} else {
				$this->sqlCheck($value, "_POST", $key);
				$this->xssCheck($value, "_POST", $key);
				$this->htmlCheck($value, "_POST", $key);
			}
		}
	}
	public function checkCOOKIE() {
		foreach ($_COOKIE as $key => $value) {
			if (is_array($value)) {
				$flattened = $this->arrayFlatten($value);
				foreach ($flattened as $sub_key => $sub_value) {
					$this->sqlCheck($sub_value, "_COOKIE", $sub_key);
					$this->xssCheck($sub_value, "_COOKIE", $sub_key);
					$this->htmlCheck($sub_value, "_COOKIE", $sub_key);
				}
			} else {
				$this->sqlCheck($value, "_COOKIE", $key);
				$this->xssCheck($value, "_COOKIE", $key);
				$this->htmlCheck($value, "_COOKIE", $key);
			}
		}
	}
	function gua() {
		if (isset($_SERVER['HTTP_USER_AGENT'])) {
			return $_SERVER['HTTP_USER_AGENT'];
		}
		return md5(rand());
	}
	function cutGua($string) {
		$five = substr($string, 0, 4);
		$last = substr($string, -3);
		return md5($five.$last);
	}
	function getCSRF() {
		if (isset($_SESSION['token'])) {
			$token_age = time() - $_SESSION['token_time'];
			if ($token_age <= 300){    /* Less than five minutes has passed. */
				return $_SESSION['token'];
			} else {
				$token = md5(uniqid(rand(), TRUE));
				$_SESSION['token'] = $token . "asd648" . $this->cutGua($this->gua());
				$_SESSION['token_time'] = time();
				return $_SESSION['token'];
			}
		} else {
			$token = md5(uniqid(rand(), TRUE));
			$_SESSION['token'] = $token . "asd648" . $this->cutGua($this->gua());
			$_SESSION['token_time'] = time();
			return $_SESSION['token'];
		}
	}
	function verifyCSRF($Value) {
		if (isset($_SESSION['token'])) {
			$token_age = time() - $_SESSION['token_time'];
			if ($token_age <= 300){    /* Less than five minutes has passed. */
				if ($Value == $_SESSION['token']) {
					$Explode = explode('asd648', $_SESSION['token']);
					$gua = $Explode[1];
					if ($this->cutGua($this->gua()) == $gua) {
						// Validated, Done!
						unset($_SESSION['token']);
						unset($_SESSION['token_time']);
						return true;
					}
					unset($_SESSION['token']);
					unset($_SESSION['token_time']);
					return false;
				}
			} else {
				return false;
			}
		} else {
			return false;
		}
	}
	public function useCloudflare() {
		$this->IPHeader = "HTTP_CF_CONNECTING_IP";
	}
	public function useBlazingfast() {
		$this->IPHeader = "X-Real-IP";
	}
	public function customIPHeader($String = 'REMOTE_ADDR') {
		$this->IPHeader = $String;
	}
	public function antiCookieSteal($listparams = 'username') {
		$this->CookieCheck = true;
		$this->CookieCheckParam = $listparams;
	}
	public function cookieCheck() {
		// Check Anti-Cookie steal trick.
		if ($this->CookieCheck == true) {
			// Check then.
			if (isset($_SESSION)) { // Session set.
				if (isset($_SESSION[$this->CookieCheckParam])) { // Logged.
					if (!(isset($_SESSION['xWAF-IP']))) {
						$_SESSION['xWAF-IP'] = $_SERVER[$this->IPHeader];
						return true;
					} else {
						if (!($_SESSION['xWAF-IP'] == $_SERVER[$this->IPHeader])) {
							// Changed IP.
							unset($_SESSION['xWAF-IP']);
							unset($_SESSION);
							@session_destroy();
							@session_start();
							return true;
						}
					}
				}
			}
		}
	}
	public function start() {
		@session_start();
		@$this->checkGET();
		@$this->checkPOST();
		@$this->checkCOOKIE();
		if ($this->CookieCheck == true) {
			$this->cookieCheck();
		}
	}

}
