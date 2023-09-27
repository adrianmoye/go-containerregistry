package registry

import (
	"encoding/json"
	"log"
	"os"
)

type manifestDiskHandler struct {
	dir string
}
type Manifest struct {
	ContentType string `json:"contentType"`
	Blob        []byte `json:"blob"`
}

func NewDiskManifestHandler(dir string) ManifestHandler { return &manifestDiskHandler{dir: dir} }

func (m manifestDiskHandler) CreateRepo(repo string, ns string) {
	if err := os.MkdirAll(m.dir+"/v2/"+repo, os.ModePerm); err != nil {
		log.Fatal(err)
	}
}

func (m manifestDiskHandler) DeleteManifest(repo, target string, ns string) {
	if err := os.Remove(m.dir + "/v2/" + repo + "/" + target); err != nil {
		log.Fatal(err)
	}
}

func (m manifestDiskHandler) ListRepos(max int, ns string) []string {
	files, err := os.ReadDir(m.dir + "/v2/" + ns + "/")
	if err != nil {
		return nil
		//log.Fatal(err)
	}
	var ret []string
	n := 0
	for _, f := range files {
		ret = append(ret, f.Name())
		n++
		if n >= max {
			break
		}
	}

	return ret
}

func (m manifestDiskHandler) GetRepo(repo string, ns string) (map[string]manifest, bool) {
	files, err := os.ReadDir(m.dir + "/v2/" + ns + "/" + repo + "/")
	if err != nil {
		return nil, err == nil
	}
	man := make(map[string]manifest)
	for _, f := range files {
		tman, _ := m.GetManifest(repo, f.Name(), ns)
		man[f.Name()] = tman
	}
	return man, (err == nil)
}

func (m manifestDiskHandler) GetManifest(repo, target string, ns string) (manifest, bool) {
	content, err := os.ReadFile(m.dir + "/v2/" + ns + "/" + repo + "/" + target)
	if err != nil {
		log.Fatal(err)
	}

	retMan := Manifest{}
	json.Unmarshal(content, &retMan)

	rval := manifest{contentType: retMan.ContentType, blob: retMan.Blob}

	return rval, (err == nil)

}

func (m manifestDiskHandler) PutManifest(repo, target string, value manifest, ns string) {

	mval := Manifest{ContentType: value.contentType, Blob: value.blob}
	dval, _ := json.Marshal(mval)

	if err := os.WriteFile(m.dir+"/v2/"+ns+"/"+repo+"/"+target, []byte(dval), 0600); err != nil {
		log.Fatal(err)
	}
}
