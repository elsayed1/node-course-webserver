import React, { Component } from 'react'
import { connect } from 'react-redux';
import { withRouter } from 'react-router-dom';
import { removeEducation } from '../../actions/profileActions';

class Education extends Component {
  render() {
    const { education } = this.props;
    console.log(education);
    let result = null;
    if(education.length === 0)
        result = (
            <div className="alert alert-danger d-block w-50 m-auto text-center">
                There is no added Education yet
            </div>
        )
    else{
        const educationRows = education.map((item, index) => {
            let endDate = null;
            if(item.to){
                endDate = item.to.slice(0, item.to.indexOf('T'));
            }
            else{
                let d = new Date();
                endDate = `${d.getFullYear()}-${d.getMonth()+1}-${d.getDate()}`;
            }
            return(
                <tr key={index}>
                    <th>{index+1}</th>
                    <td>{item.school}</td>
                    <td>{item.degree}</td>
                    <td>{item.fieldOfStudy}</td>
                    <td>{item.from.slice(0, item.from.indexOf('T')) + ' :: ' + endDate}</td>
                    <td>
                        <button 
                        className="btn btn-danger"
                        onClick={(e) => {
                            e.preventDefault();
                            if(window.confirm('Are you sure you want to delete Education ?')){
                                this.props.removeEducation(item._id);
                            }
                        }}>
                            Delete
                        </button>
                    </td>
                </tr>
            )
        });
        result = (
            <table className="table table-striped">
                <thead>
                    <tr>
                    <th>#</th>
                    <th>School</th>
                    <th>Degree</th>
                    <th>Field Of Study</th>
                    <th>Years</th>
                    <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {educationRows}
                </tbody>
            </table>
        )
    }
    return(
        <div className='education'>
            <div className='container'>
                <div className='row'>
                    <div className='col-md-12'>
                        <h2 className="text-info mb-5">
                            <span style={{
                                borderBottom: '4px solid #17a2b8',
                                paddingBottom: '5px'
                            }}>Educa</span>tion Section
                        </h2>
                        {result}
                    </div>
                </div>
            </div>
        </div>
    )
  }
}
export default connect(null, { removeEducation })(withRouter(Education));
