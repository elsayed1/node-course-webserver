import React from 'react';
import classnames from 'classnames';
function TextAreaFieldGroup({
    errors,
    id,
    placeholder,
    value,
    name,
    type,
    icon,
    changeSocialInput
}) {
  return (
    <div className='row my-3'>
    <div className="input-group col-md-8">
        <div className='input-group-prepend'>
            <div className='input-group-text'>
                <i className={icon} />
            </div>
        </div>
        <input 
        className= {classnames("form-control", {
        'is-invalid': errors[name],
        })}
        id={id}
        name={name}
        type={type}
        aria-describedby="emailHelp" 
        placeholder={placeholder}
        defaultValue={value} 
        onChange={changeSocialInput}
        />
        {errors[name]?(
        <small className='form-text text-danger'>
            {errors[name]}
        </small>
        ):null}
  </div>
  </div>
  )
}
export default TextAreaFieldGroup;
