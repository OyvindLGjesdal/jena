<!--
   Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements.  See the NOTICE file distributed with
   this work for additional information regarding copyright ownership.
   The ASF licenses this file to You under the Apache License, Version 2.0
   (the "License"); you may not use this file except in compliance with
   the License.  You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
-->

<template>
  <nav class="navbar md:navbar-expand bg-1">
    <div class="container-fluid mx-3 md:mx-0">
      <router-link to="/" class="navbar-brand">
        <img alt="Apache Jena logo" src="../assets/logo.svg" style="width: 52px;"> Apache Jena Fuseki
      </router-link>
      <button class="btn-icon navbar-toggler" type="button" data-bs-toggle="drawer" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon" aria-hidden="true"></span>
      </button>
      <dialog ref="navbarDrawer" class="drawer drawer-end" tabindex="-1" id="navbarNav" aria-labelledby="navbarNavLabel">
        <div class="drawer-header">
          <h5 class="drawer-title" id="navbarNavLabel">
            Apache Jena Fuseki
          </h5>
          <button type="button" class="btn-close" data-bs-dismiss="drawer" aria-label="Close"></button>
        </div>
        <div class="drawer-body">
          <ul class="nav navbar-nav">
            <li class="nav-item">
              <router-link to="/" class="nav-link" exact-active-class="active">
                <FontAwesomeIcon icon="database" /> datasets
              </router-link>
            </li>
            <li class="nav-item">
              <router-link to="/manage" class="nav-link" exact-active-class="active">
                <FontAwesomeIcon icon="cogs" /> manage
              </router-link>
            </li>
            <li class="nav-item">
              <router-link to="/documentation" class="nav-link" exact-active-class="active">
                <FontAwesomeIcon icon="info-circle" /> help
              </router-link>
            </li>
          </ul>
          <ul class="nav navbar-nav ms-auto">
            <ServerStatus />
          </ul>
        </div>
      </dialog>
    </div>
  </nav>
</template>

<script>
import { library } from '@fortawesome/fontawesome-svg-core'
import { faDatabase, faCogs, faInfoCircle } from '@fortawesome/free-solid-svg-icons'
import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome'
import { Drawer } from 'bootstrap/dist/js/bootstrap.bundle.min.js'
import ServerStatus from '@/components/ServerStatus.vue'

library.add(faDatabase, faCogs, faInfoCircle)

export default {
  name: 'Menu',

  components: {
    FontAwesomeIcon,
    ServerStatus
  },

  watch: {
    // Below the md breakpoint the nav is a modal drawer, which stays open over the new page after
    // a router-link navigates, so close it on every route change.
    $route () {
      Drawer.getInstance(this.$refs.navbarDrawer)?.hide()
    }
  }
}
</script>
