<?php

class Notes {

    private $db;

    public function __construct() {
        $this->_db = new Db();
    }

    public function create($uid, $data) {
        $note = [
            "uid" => $uid,
            "last_change" => time(),
            "title" => $data->title,
            "content" => $data->content
            ];
        
            return $this->_db->getStore('notes')->insert($note);
    }

    // @TODO add $typ=filter to select notes 
    public function read($id, $typ) {
        if(strcmp($typ, 'single') === 0) {
            return $this->_db->getStore('notes')->findOneBy(["_id", "=", $id]);
        }
        else {
            $notes = $this->_db->getStore('notes')->findBy(["uid", "=", $id]);
            $note_list_data = array();

            foreach ($notes as $note) {
                $note_list_entry = array(
                    "title" => $note['title'],
                    "teaser" => (str_split($note['content'], 40)[0]),
                    "last_change" => $note['last_change'],
                    "id" => $note['_id']
                    );
                array_push($note_list_data, $note_list_entry);
            }

            return $note_list_data;
        }


    }

    public function update($uid, $data) {
        $note = [
            "uid" => $uid,
            "last_change" => time(),
            "title" => $data->title,
            "content" => $data->content,
            "_id" => $data->id
            ];
        
        return $this->_db->getStore('notes')->updateOrInsert($note);
    }

    public function delete($id) {
        return $this->_db->getStore('notes')->deleteBy(['_id', '=', $id]);
    }
    //crud
}
?>