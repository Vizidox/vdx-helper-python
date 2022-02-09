===========
Quick Start
===========

This chapter provides you instructions on how to start using the VDX Helper library, including how to install it
and some examples of usage. Make sure to also consult the `Vizidox Core API Documentation <https://docs.vizidox.com>`__
documentation, since both these documentations complement each other.

Requirements & Installation
****************************

This library requires Python 3.7 or later to run. To install, you can use Pip or any other Python dependency manager:

.. code-block:: shell

    python -m pip install vdx-helper

Examples & Usage
******************

Read each sub-section to learn how you can use the VDX Helper library to upload a file and issue it onto the Blockchain,
guaranteeing its ownership.
This guide will teach you how to use the several methods available to you on the VDX Helper class. However, to learn
more about the specific parameters on each method/endpoint, the `VDX Core API documentation <https://docs.vizidox.com>`__
explains these in more detail.

Initialize the VDXHelper
=========================

First and foremost, you must initialize an instance of the VDXHelper class, by providing your authentication details.
The example below works for the production environment, however if you are using the sandbox/demo environment, just change
the api_url and auth_url values for the correct ones.

.. code-block:: python
    :caption: VDX Helper Initialization
    :linenos:
    :name: initialize-vdx-helper

    from vdx_helper import VDXHelper

    vdx_helper = VDXHelper(api_url="https://vizidox.com/api",
                           auth_url="https://vizidox.com/auth",
                           client_secret="secret", client_id="id")

Upload Your File
================

If you want to issue a file to the Blockchain through the VDX Core API, then you must first upload that file.
To do so, use the :meth:`upload_file <vdx_helper.vdx_helper.VDXHelper.upload_file>` method available on the VDX Helper
class, and pass in a file stream. Optionally, you can change the "ignore_duplicated" flag (which is false by default),
meaning that any uploaded files that are duplicates will be ignored and no error is returned in that case.

An instance of :class:`File <vdx_helper.models.File>`, containing the details of the uploaded file,
is returned by this method.

It should be noted that although the file hash is stored on the VDX Core API server, for verification purposes, the
original file is never stored.


.. code-block:: python
    :caption: File Upload
    :linenos:
    :emphasize-lines: 5
    :name: upload-file

    from vdx_helper import VDXError
    with open('example.txt', 'r') as open_file:
        file_stream = f.read()
    try:
        file = vdx_helper.upload_file(file_stream=file_stream, ignore_duplicated=True)
    except VDXError as error:
        # Handle exception


Create & Schedule Credential
=============================

A Credential is the fingerprint of a file, metadata or both, that is hashed and issued on the Blockchain. Use
:meth:`create_credential <vdx_helper.vdx_helper.VDXHelper.create_credential>` to create a Credential, which is required
for all Blockchain issuings. For the credential to be successfully created, you are required to provide at least one
file hash, or a non-empty metadata dictionary.

Use the file hash(es) obtained from the :ref:`file upload <upload-file>` to fill in the
"file_hashes" parameter, if you want to issue a file.

To connect credentials, creating a single record, optionally pass in uuids from previously created credentials on the
"cred_ids" parameter.

An instance of :class:`Credential <vdx_helper.models.Credential>`, containing the details of the created
credential, is returned by this method.

.. code-block:: python
    :caption: Credential Creation
    :linenos:
    :emphasize-lines: 6, 7, 8, 9, 10, 11
    :name: create-credential

    from vdx_helper import VDXError
    from datetime import datetime
    try:
        expiry_date = datetime.now(pytz.UTC)
        expiry_date = expiry_date.replace(year = expiry_date.year + 1)
        credential = vdx_helper.create_credential(title="Joja Employment Contract",
                                                  metadata={"Position": "Clerk", "name": "Shane"},
                                                  tags=["contract_2021"],
                                                  file_hashes=["86df179f301cb1d858065f5783acb3d5"],
                                                  cred_ids=["14027b08-4966-11ec-81d3-0242ac130003"],
                                                  expiry_date=expiry_date)
    except VDXError as error:
        # Handle exception

A credential has now been created and successfully stored on the VDX Core API database; however, it has not yet been
recorded on the Blockchain. To get this to happen, you need to schedule the Credential on a specific Blockchain engine,
and will be issued on the next scheduled date.

Use :meth:`schedule_credentials <vdx_helper.vdx_helper.VDXHelper.schedule_credentials>` to schedule one or more
Credentials on a specific Blockchain. You only need to provide the Blockchain engine, and a list of the credential
UUIDs to be scheduled.

The current scheduled :class:`Job <vdx_helper.models.Job>` is returned, including the scheduled date for
issuing.

.. code-block:: python
    :caption: Schedule Credential
    :linenos:
    :emphasize-lines: 3, 4
    :name: schedule-credential

    from vdx_helper import VDXError
    try:
        scheduled_job = vdx_helper.schedule_credentials(engine="bitcoin",
                                                        credentials=["5c6b45ea-5d8f-43ef-8b3e-cc4176976cb4"])
    except VDXError as error:
        # Handle exception

.. warning::
    A Credential is never issued on any Blockchain without explicitly calling the "schedule credential" method/endpoint

Check if Your Job Has Been Issued
=================================

After scheduling your credential(s) for issuing on any of the available Blockchain Engines, you have to wait until
the next scheduled date for issuing. If you want to check if the job has already been issued on the Blockchain,
retrieve it from the Core API with :meth:`get_job <vdx_helper.vdx_helper.VDXHelper.get_job>`, using the job UUID obtained
when scheduling the Credential.

.. code-block:: python
    :caption: Job Retrieval
    :linenos:
    :emphasize-lines: 2
    :name: get-job

    from vdx_helper import VDXError
    try:
        job = vdx_helper.get_job("93bf19f0-4966-11ec-81d3-0242ac130003")
    except VDXError as error:
        # Handle exception

The :class:`Job <vdx_helper.models.Job>` corresponding to the given UUID is returned, including all its details. The
status of the Job will determine if it has already been issued. If the Job is either in the Unconfirmed or Finished
status, then your credentials have been recorded on the Blockchain and you can safely share them. The time it takes
to change from Unconfirmed to Finished will vary, depending on the Blockchain Engine of choice. For example, on Bitcoin,
this can take up to ten minutes.

.. list-table:: Job Status
   :widths: 25 75
   :header-rows: 1

   * - Status
     - Description
   * - Scheduled
     - The job has not been issued yet, but it is scheduled
   * - Started
     - The job issuing process has started
   * - Unconfirmed
     - The job issuing process was successful, but the Blockchain transaction has not been confirmed yet
   * - Finished
     - The job issuing transaction was confirmed on the Blockchain
   * - Failed
     - Something unexpected occurred and the job issuing failed. You will need to re-schedule the credentials

With the Job in an Unconfirmed or Finished status, you can also retrieve the issued Credentials' Certificates, which
contain the proof of issuing. To do this, call the :meth:`get_job_certificates <vdx_helper.vdx_helper.VDXHelper.get_job_certificates>`
method to obtain all the issued certificates in a specific job, passing in the job UUID. The example below also shows
how the pagination parameters can be used - a dictionary containing the parameters you want to send can be used as keyword arguments.
In this specific example, we are requesting the first fifty results (page 1, with 50 items per page). The default values
are used for the unmentioned parameters. Read more on the pagination parameters `here <https://docs.vizidox.com/#pagination>`__.

A list of :class:`Certificate <vdx_helper.models.Certificate>` objects are returned, which all have been issued in the
given Job, and each directly correspond to one Credential scheduled on the Job.

.. code-block:: python
    :caption: Job Certificates Retrieval
    :linenos:
    :emphasize-lines: 7, 8
    :name: get-job-certificates

    pagination = {
        'per_page': 50,
        'page': 1
    }

    try:
        core_certificates = vdx_helper.get_job_certificates(job_uid="93bf19f0-4966-11ec-81d3-0242ac130003",
                                                            **pagination)
    except VDXError as error:
        # Handle exception

Verify Certificate
===================

Finally, with your credentials fully issued on the Blockchain and your certificates obtained, these can be easily
verified as many times as required to guarantee that they have not been tampered with. Several different verification
options are available, and fully documented `here <https://docs.vizidox.com>`__, however in this example we will
be demonstrating the verification by certificate UUID.

The Certificate verification process consists of six different steps, and if all pass then the corresponding credential
is considered valid and has not been tampered with. Each step has its own individual result (ok, pending, expired, revoked,
failed or error), and the final result of the verification will depend on all of the steps' results.

.. code-block:: python
    :caption: Verification
    :linenos:
    :emphasize-lines: 2
    :name: verify

    try:
        verification = verify_by_uid(cert_uid="93bf19f0-4966-11ec-81d3-0242ac130003")
    except VDXError as error:
        # Handle exception

By default, any of the verification methods will return a :class:`Verification <vdx_helper.models.Verification>` object,
which not only contains a list with the results and descriptions of each individual steps, as well as the final result
for the full process. Some of the methods may return more than one verification result, since a single credential
can have more than one certificate (one for each blockchain engine); in this case, the result will be a list of
:class:`Paginated <vdx_helper.models.PaginatedResponse>` objects, with each verification result listed as an item.

Mappers
********

Mappers are an extra, optional, feature provided by the VDX Helper library. All methods that return a complex object
allow you to pass a specific parameter, called a *mapper* which serializes the JSON returned from the endpoint request
to any format that might be useful for you. So instead of having to call a serializing function after every
VDX Helper method call, or even manually accessing a JSON and/or one of the Helper's models, the VDX Helper methods
will do this for you.

In all the examples previously displayed, no mappers were defined, so the methods used the default
:mod:`mappers <vdx_helper.mappers>`. For example, when retrieving a Credential, the default
:meth:`credential mapper <vdx_helper.mappers.credential_mapper>` will serialize the JSON response into a
:class:`Credential <vdx_helper.models.Credential>`.

If, for example, in your own application, you have an :class:`IssuedContract` class, that could be defined as follows:

.. code-block:: python
    :caption: IssuedContract class
    :linenos:
    :name: issued-contract

    class IssuedContract
        title: str
        employee_name: str
        contract_start_date: datetime
        issued_date: datetime
        expiry_date: datetime


All the fields in this class can be filled in from the information provided in a Credential object, so when retrieving
a Credential from the Core API, it is more useful to directly have it instantiate the :class:`IssuedContract` class for you.
To do so, create a mapper method and pass it in to the :meth:`get credential <vdx_helper.vdx_helper.VDXHelper.get_credential>` method.

.. code-block:: python
    :caption: Creating and Using a Mapper
    :linenos:
    :emphasize-lines: 8
    :name: issued-contract-mapper

    def issued_contract_mapper(credential_json: dict) -> IssuedContract:
        return IssuedContract(credential_json['title'],
                              credential_json['metadata']['employee_name'],
                              credential_json['metadata']['contract_start_date'],
                              credential_json['issued_date'],
                              credential_json['expiry_date'])

    issued_contract = vdx_helper.get_credential("93bf19f0-4966-11ec-81d3-0242ac130003", mapper=issued_contract_mapper)


