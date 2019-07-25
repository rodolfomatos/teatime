<?php

// Port of https://github.com/Alemalakra/xWAF to composer
namespace rodolfomatos\teatime;
class cup
{
	//------------------------------------------------------------------
    public function drink($comment = "It's teatime!")
    {
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
	public function writeToLog($event) {
		$logfile='/var/log/teatime.log';
			try {
				if(!file_exists($logfile)) {
						$log="#<?php die('Forbidden.'); ?>\n";
						$log .= "#[<timestamp>][<event>][<request>][<userid>][<remote_address>][<host>][<referer>][<session_id>]\n";
				} else {
						$log="";
				}
				date_default_timezone_set($CFG->timezone);
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
		die(); // Block request.
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
