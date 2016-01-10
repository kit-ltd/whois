<?php
/* 
 * ...
 * 
 * @author    Anton Popov <an.popov@list.ru>
 * @copyright Copyright (c) 2016 KIT Ltd.
 */

namespace Whois;

class Domain
{
    private $domain;
    private $tld;
    private $subdomain;
    private $servers;
    
    public function __construct($domain)
    {
        $this->domain = $domain;
        if (false === preg_match('/^([\p{L}\d\-]+)\.((?:[\p{L}\-]+\.?)+)$/ui', $this->domain, $matches)) {
            preg_match('/^(xn\-\-[\p{L}\d\-]+)\.(xn\-\-(?:[a-z\d-]+\.?1?)+)$/ui', $this->domain, $matches);
        }
        if (false === empty($matches)) {
            $this->subdomain = $matches[1];
            $this->tld = $matches[2];
        } else {
            throw new \InvalidArgumentException("Invalid $domain syntax");
        }
        $this->servers = json_decode(file_get_contents(__DIR__ .'/servers.json'), true);
    }
    
    public function info()
    {
        if ($this->isValid()) {
            if ($server = $this->servers[$this->tld][0]) {
                if (preg_match("/^https?:\/\//i", $server)) {
                    $ch = curl_init();
                    $url = $server . $this->subdomain . '.' . $this->tld;
                    curl_setopt($ch, CURLOPT_URL, $url);
                    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
                    curl_setopt($ch, CURLOPT_TIMEOUT, 60);
                    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
                    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
                    $data = curl_exec($ch);
                    if (curl_error($ch)) {
                        return "Connection error!";
                    } else {
                        $string = strip_tags($data);
                    }
                    curl_close($ch);
                } else {
                    $fp = fsockopen($server, 43);
                    if (!$fp) {
                        return "Connection error!";
                    }
                    $domain = $this->subdomain . '.' . $this->tld;
                    fputs($fp, "$domain\r\n");
                    $string = '';
                    if ($this->tld == 'com' || $this->tld == 'net') {
                        while (!feof($fp)) {
                            $line = trim(fgets($fp, 128));
                            $string .= $line;
                            $lineArr = explode (":", $line);
                            if (strtolower($lineArr[0]) == 'whois server') {
                                $server = trim($lineArr[1]);
                            }
                        }
                        $fp = fsockopen($server, 43);
                        if (!$fp) {
                            return "Connection error!";
                        }
                        $domain = $this->subdomain . '.' . $this->tld;
                        fputs($fp, "$domain\r\n");
                        $string = '';
                        while (!feof($fp)) {
                            $string .= fgets($fp, 128);
                        }
                    } else {
                        while (!feof($fp)) {
                            $string .= fgets($fp, 128);
                        }
                    }
                    fclose($fp);
                }
                $string_encoding = mb_detect_encoding($string, "UTF-8, ISO-8859-1, ISO-8859-15", true);
                $string_utf8 = mb_convert_encoding($string, "UTF-8", $string_encoding);
                return htmlspecialchars($string_utf8, ENT_COMPAT, "UTF-8", true);
            }
        } else {
            return "Domain name isn't valid!";
        }
    }
    
    public function isAvailable()
    {
        $whois = $this->info();
        $notFound = '';
        if (isset($this->servers[$this->tld][1])) {
            $notFound = $this->servers[$this->tld][1];
        }
        $whois2 = @preg_replace('/' . $this->domain . '/', '', $whois);
        $whois = @preg_replace("/\s+/", ' ', $whois);
        $array = explode (":", $notFound);
        if ($array[0] == "MAXCHARS") {
            if (strlen($whois2) <= $array[1]) {
                return true;
            }
        } else {
            if (preg_match("/" . $notFound . "/i", $whois)) {
                return true;
            }
        }
        return false;
    }
    
    public function getDomain()
    {
        return $this->domain;
    }
    
    public function getTld()
    {
        return $this->tld;
    }
    
    public function getSubdomain()
    {
        return $this->subdomain;
    }
    
    public function isValid()
    {
        if (isset($this->servers[$this->tld][0]) && strlen($this->servers[$this->tld][0]) > 6) {
            $subdomain = strtolower($this->subdomain);
            //&& !preg_match("/--/", $subdomain)
            if (preg_match("/^[a-z0-9\-]{3,}$/", $subdomain) && !preg_match("/^-|-$/", $subdomain)) {
                return true;
            }
        }
        return false;
    }
}
