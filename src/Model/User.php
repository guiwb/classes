<?php 

namespace guiwb\Model;

use \guiwb\DB\Sql;
use \guiwb\Model;
use \guiwb\Mailer;

class User extends Model {

	const SESSION = "User";
	const SESSION_ERROR = "UserError";
	const SESSION_SUCCESS = "UserSuccess";
	const SECRET = "UserCodeUltraSecret";

	// LOGIN, LOGOUT AND GETS

	public static function login($login, $password)
	{

		$sql = new Sql();

		$results = $sql->select("
			SELECT *
			FROM tb_users
			WHERE deslogin = :LOGIN
			", [
				":LOGIN"=>$login
			]);


		if (count($results) === 0) {

			throw new \Exception("Usuário inexistente ou senha inválida.");

		}

		$data = $results[0];

		if (password_verify($password, $data["despassword"])) {

			$user = new User();

			$user->setData($data);

			$_SESSION[User::SESSION] = $user->getValues();

			return $user;

		} else {

			throw new \Exception("Usuário inexistente ou senha inválida.");

		}

	}



	public static function checkLogin($inadmin = true)
	{

		if (!isset($_SESSION[User::SESSION]) || !$_SESSION[User::SESSION] || !(int)$_SESSION[User::SESSION]["iduser"] > 0) {

			return false;

		} else {

			if ($inadmin === true && (bool)$_SESSION[User::SESSION]['inadmin'] === true) {

				return true;

			} else if ($inadmin === false) {

				return true;

			} else {

				return false;
				
			}

		}
		
	}



	public static function verifyLogin($inadmin = true)
	{

		if (!User::checkLogin($inadmin)) {

			if ($inadmin) {

				header("Location: /admin/login");

			} else {

				header("Location: /login");

			}

			exit;

		}

	}



	public static function logout()
	{

		$_SESSION[User::SESSION] = NULL;

	}



	public function get(int $iduser)
	{

		$sql = new Sql();

		$results = $sql->select("SELECT * FROM tb_users WHERE iduser = :iduser", [
			":iduser" => $iduser
		]);

		$this->setData($results[0]);

	}



	public static function getFromSession()
	{

		$user = new User();

		if (isset($_SESSION[User::SESSION]) && (int)$_SESSION[User::SESSION]['iduser'] > 0) {

			$user->setData($_SESSION[User::SESSION]);

		}

		return $user;

	}



	// CRUD

	public function save()
	{

		User::verifyExist($this->getiduser(), $this->getdeslogin(), $this->getdesemail(), $this->getnrphone(), '/admin/users/create');

		$sql = new Sql();

		$results = $sql->select("CALL sp_users_save(:iduser, :desname, :deslogin, :despassword, :desemail, :nrphone, :inadmin)", [
			":iduser" => $this->getiduser(),
			":desname" => $this->getdesname(),
			":deslogin" => $this->getdeslogin(),
			":despassword" => User::getPasswordHash($this->getdespassword()),
			":desemail" => $this->getdesemail(),
			":nrphone" => $this->getnrphone(),
			":inadmin" => $this->getinadmin()
		]);

		$this->setData($results[0]);

	}



	public function delete()
	{

		$sql = new Sql();

		$sql->query("CALL sp_users_delete(:iduser)", [
			":iduser" => $this->getiduser()
		]);

	}



	// FORGOT

	public static function getForgot($email, $inadmin = true)
	{

		$sql = new Sql();

		$results = $sql->select("SELECT * FROM tb_users WHERE desemail = :email", [
			":email" => $email
		]);

		if (count($results) === 0) {

			throw new \Exception("Não foi possível recuperar a senha.");

		} else {

			$data = $results[0];

			$results2 = $sql->select("CALL sp_userspasswordsrecoveries_create(:iduser, :desip)", [
				":iduser" => $data["iduser"],
				":desip" => $_SERVER["REMOTE_ADDR"]
			]);

			if (count($results2) === 0) {

				throw new \Exception("Não foi possível recuperar a senha.");

			} else {

				$data2 = $results2[0];

				$iv = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
				$code = openssl_encrypt($data2['idrecovery'], 'aes-256-cbc', User::SECRET, 0, $iv);
				$result = base64_encode($iv.$code);

				if ($inadmin === true) {

					$link = "http://www.site.com.br/admin/forgot/reset?code=$result";

				} else {

					$link = "http://www.site.com.br/forgot/reset?code=$result";

				}

				$mailer = new Mailer($data["desemail"], $data["desname"], "Redefinir Senha da Hcode Store", "forgot", [
					"name" => $data["desname"],
					"link" => $link
				]);

				$mailer->send();

				return $data;

			}

		}

	}



	public static function validForgotDecrypt($result)
	{

		$result = base64_decode($result);
		$code = mb_substr($result, openssl_cipher_iv_length('aes-256-cbc'), null, '8bit');
		$iv = mb_substr($result, 0, openssl_cipher_iv_length('aes-256-cbc'), '8bit');
		$idrecovery = openssl_decrypt($code, 'aes-256-cbc', User::SECRET, 0, $iv);

		$sql = new Sql();

		$results = $sql->select("SELECT * FROM tb_userspasswordsrecoveries a INNER JOIN tb_users b USING(iduser) WHERE a.idrecovery = :idrecovery AND
			a.dtrecovery IS NULL AND DATE_ADD(a.dtregister, INTERVAL 1 HOUR) >= NOW()", [
				":idrecovery"=>$idrecovery
			]);

		if (count($results) === 0) {
			throw new \Exception("Não foi possível recuperar a senha.");
		} else {
			return $results[0];
		}

	}



	public static function setForgotUsed($idrecovery)
	{

		$sql = new Sql();

		$sql->query("UPDATE tb_userspasswordsrecoveries SET dtrecovery = NOW() WHERE idrecovery = :idrecovery", [
			":idrecovery" => $idrecovery
		]);

	}



	// MESSAGES

	public static function setError($msg)
	{

		$_SESSION[User::SESSION_ERROR] = $msg;

	}

	public static function getError()
	{

		$msg = (isset($_SESSION[User::SESSION_ERROR])) ? $_SESSION[User::SESSION_ERROR] : '';

		User::clearError();

		return $msg;

	}

	public static function clearError()
	{

		$_SESSION[User::SESSION_ERROR] = null;

	}

	public static function setSuccess($msg)
	{

		$_SESSION[User::SESSION_SUCCESS] = $msg;

	}

	public static function getSuccess()
	{

		$msg = (isset($_SESSION[User::SESSION_SUCCESS])) ? $_SESSION[User::SESSION_SUCCESS] : '';

		User::clearSuccess();

		return $msg;

	}

	public static function clearSuccess()
	{

		$_SESSION[User::SESSION_SUCCESS] = null;

	}



	// OTHERS

	public static function listAll()
	{

		$sql = new Sql();

		return $sql->select("SELECT * FROM tb_users ORDER BY desname");

	}



	public static function verifyExist($iduser, $deslogin, $desemail, $nrphone, $redirect)
	{

		$sql = new Sql();

		if ((int)$iduser > 0) {
			$results = $sql->select("SELECT * FROM tb_users WHERE iduser <> :iduser AND (deslogin = :deslogin OR desemail = :desemail)", [
				':iduser'=>$iduser,
				':deslogin'=>$deslogin,
				':desemail'=>$desemail
			]);
		} else {
			$results = $sql->select("SELECT * FROM tb_users WHERE deslogin = :deslogin OR desemail = :desemail", [
				':deslogin'=>$deslogin,
				':desemail'=>$desemail,
				':nrphone'=>$nrphone
			]);
		}

		if (count($results) > 0) {

			User::setError("Já existe um usuário com estas informações!");
			header("Location: $redirect");
			exit;

		}

	}

	public static function getPasswordHash($password)
	{

		return password_hash($password, PASSWORD_DEFAULT, [
			'cost'=>12
		]);
		
	}

}

?>